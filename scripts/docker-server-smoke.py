#!/usr/bin/env python3
"""Actual image -> authenticated server services -> disposable PostgreSQL.

Only uniquely named fixture containers, network and volume are created. No
owner service, environment file, database or provider credential is accessed.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid

repo = pathlib.Path(__file__).resolve().parents[1]
server = repo.parent / 'authrail-server'
node = repo.parent / 'authrail-sdk-node'
go = repo.parent / 'authrail-sdk-go'
image = sys.argv[1] if len(sys.argv)>1 else 'authrail-sidecar:development'
prefix = 'authrail-server-image-' + uuid.uuid4().hex[:10]
network, database, runner, daemon, volume = [prefix+'-'+part for part in ['net','pg','runner','sidecar','state']]

def docker(*args, check=True, timeout=120):
    return subprocess.run(['docker',*args],check=check,timeout=timeout,capture_output=True,text=True)

def wait_file(path, container, seconds=90):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        if path.exists(): return
        if docker('inspect',container,'--format','{{.State.Running}}').stdout.strip()!='true':
            raise RuntimeError('Fixture exited before '+path.name)
        time.sleep(.1)
    raise RuntimeError('Timed out waiting for '+path.name)

try:
    with tempfile.TemporaryDirectory(prefix=prefix) as scratch:
        directory=pathlib.Path(scratch)
        architecture=docker('image','inspect','authrail-api:latest','--format','{{.Architecture}}').stdout.strip()
        (directory/'go.work').write_text('go 1.26.0\nuse '+json.dumps(str(go))+'\n')
        subprocess.run(['go','build','-trimpath','-o',str(directory/'go-client'),str(repo/'scripts/docker-server-smoke.go')],env=dict(os.environ,GOWORK=str(directory/'go.work'),CGO_ENABLED='0',GOOS='linux',GOARCH=architecture),check=True)
        (directory/'migrate.ts').write_text("import { Pool } from 'pg';\nimport { migratePostgresDatabase } from '/app/src/infra/database/migrate-postgres-database';\nconst pool=new Pool({connectionString:process.env.DATABASE_URL,max:1});\nasync function main(){const client=await pool.connect();try{await migratePostgresDatabase(client,{migrationsFolder:'/app/drizzle'});}finally{client.release();await pool.end();}}\nvoid main().catch(error=>{console.error(error);process.exitCode=1;});\n")
        docker('network','create',network)
        docker('volume','create',volume)
        docker('run','-d','--name',database,'--network',network,'--network-alias','postgres','-e','POSTGRES_USER=fixture','-e','POSTGRES_PASSWORD=isolated-fixture-only','-e','POSTGRES_DB=authrail_slice5_image','pgvector/pgvector:pg17')
        for attempt in range(100):
            if docker('exec',database,'pg_isready','-U','fixture','-d','authrail_slice5_image',check=False).returncode==0: break
            time.sleep(.2)
        else: raise RuntimeError('Disposable PostgreSQL did not become ready')
        common=['--network',network,'-w','/app','--mount','type=bind,src='+str(server/'src')+',dst=/app/src,readonly','--mount','type=bind,src='+str(server/'drizzle')+',dst=/app/drizzle,readonly','--mount','type=bind,src='+str(server/'tsconfig.json')+',dst=/app/tsconfig.json,readonly','--mount','type=bind,src='+scratch+',dst=/fixture','-e','DATABASE_URL=postgres://fixture:isolated-fixture-only@postgres:5432/authrail_slice5_image','-e','OTEL_SDK_ENABLED=false']
        result=docker('run','--rm',*common,'--mount','type=bind,src='+str(directory/'migrate.ts')+',dst=/app/authrail-migrate.ts,readonly','authrail-api:latest','npx','tsx','/app/authrail-migrate.ts')
        print('Disposable PostgreSQL migrations passed')
        docker('run','-d','--name',runner,*common,'--mount','type=bind,src='+str(node)+',dst=/workspace/authrail-sdk-node,readonly','--mount','type=bind,src='+str(repo/'scripts/docker-server-smoke.mjs')+',dst=/tmp/authrail-slice5-node-client.mjs,readonly','--mount','type=bind,src='+str(directory/'go-client')+',dst=/tmp/authrail-slice5-go-client-bin,readonly','-e','AUTHRAIL_LOCAL_RUNTIME_VERIFICATION=1','-e','AUTHRAIL_CONNECTED_VERIFY=1','-e','AUTHRAIL_CONNECTED_DOCKER_CONFIG=/tmp/authrail-image-fixture/config.json','--mount','type=bind,src='+scratch+',dst=/tmp/authrail-image-fixture','authrail-api:latest','npx','tsx','src/runtime/test/verification/runtime-observe.persistence.ts')
        config_path=directory/'config.json'
        wait_file(config_path,runner)
        configuration=json.loads(config_path.read_text())
        public_key=directory/'executor-public.pem'
        docker('cp',runner+':'+configuration['publicKeyFile'],str(public_key))
        public_key.chmod(0o444)
        arguments=['run','-d','--name',daemon,'--network','container:'+runner,'--read-only','--cap-drop','ALL','--security-opt','no-new-privileges:true','--mount','type=volume,src='+volume+',dst=/var/lib/authrail','--mount','type=bind,src='+str(public_key)+',dst=/run/executor-public.pem,readonly','-e','AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE=/run/executor-public.pem']
        for name,value in configuration['environment'].items(): arguments.extend(['-e',name+'='+value])
        docker(*arguments,image)
        # Restart the same container/whole-state volume only at the fixture's
        # explicit phase boundary, while its control plane remains available.
        stop=directory/'config.json.stop'
        restart=directory/'config.json.restart'
        restarted=directory/'config.json.restarted'
        deadline=time.monotonic()+120
        while not stop.exists():
            if restart.exists() and not restarted.exists():
                docker('restart','-t','10',daemon)
                restarted.touch(mode=0o600)
            if docker('inspect',runner,'--format','{{.State.Running}}').stdout.strip()!='true':
                raise RuntimeError('Server fixture exited before shutdown acknowledgement')
            if time.monotonic()>deadline:
                raise RuntimeError('Server fixture did not request shutdown')
            time.sleep(.1)
        docker('stop','-t','10',daemon)
        (directory/'config.json.stopped').touch(mode=0o600)
        status=docker('wait',runner).stdout.strip()
        logs=docker('logs',runner)
        print(logs.stdout,end='')
        if status!='0':
            print(logs.stderr,file=sys.stderr)
            raise RuntimeError('Server verification exited '+status)
        execution=docker('run','--rm',*common,'-e','AUTHRAIL_LOCAL_RUNTIME_VERIFICATION=1','authrail-api:latest','npx','tsx','src/runtime/test/verification/runtime-execution.persistence.ts')
        print(execution.stdout,end='')
        print('PASS: Docker sidecar + Node/Go SDKs + authenticated real server services + disposable PostgreSQL retained call/result certificates, logs and fresh health; rollback and execution recovery verified')
except (subprocess.SubprocessError,RuntimeError,AssertionError) as error:
    print('Docker server smoke failed:',error,file=sys.stderr)
    for container in (runner,daemon):
        logs=docker('logs',container,check=False)
        print(logs.stdout+logs.stderr,file=sys.stderr)
    sys.exit(1)
finally:
    docker('rm','-f',daemon,runner,database,check=False)
    docker('volume','rm',volume,check=False)
    docker('network','rm',network,check=False)
