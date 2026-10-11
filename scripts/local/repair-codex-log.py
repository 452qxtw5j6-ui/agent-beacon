#!/usr/bin/env python3
"""Repair local Codex provenance and per-completion usage, preserving event IDs.
Run with --apply only after stopping the collector; cooperates with hook log locks.
"""
import argparse, collections, datetime, fcntl, json, os, pathlib, shutil
arg=argparse.ArgumentParser();arg.add_argument('--apply',action='store_true');args=arg.parse_args()
base=pathlib.Path.home()/'.beacon/endpoint/logs'
lock=open(base/'runtime.jsonl.lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
files=sorted(f for f in base.glob('runtime.jsonl*') if f.name=='runtime.jsonl' or f.name.removeprefix('runtime.jsonl.').isdigit())
data={f:[json.loads(l) for l in f.open() if l.strip()] for f in files}
sids={e.get('session',{}).get('id') for events in data.values() for e in events if e.get('harness',{}).get('name','').startswith('codex')}
source={}
for f in (pathlib.Path.home()/'.codex/sessions').rglob('*.jsonl'):
 for sid in sids:
  if sid and f.name.endswith(sid+'.jsonl'):source[sid]=f
meta={};usage={}
fields=['input_tokens','cached_input_tokens','cache_write_input_tokens','output_tokens','reasoning_output_tokens','total_tokens']
for sid,f in source.items():
 turns={}
 for number,l in enumerate(f.open(),1):
  try:r=json.loads(l)
  except json.JSONDecodeError:continue
  p=r.get('payload',{})
  if r.get('type')=='session_meta':meta[sid]=p
  if r.get('type')!='token_usage_record':continue
  total=p.get('turn_token_usage');turn=p.get('turn_id','');u=p.get('usage')
  if u is None and total is not None:
   previous=turns.get(turn,{})
   u={k:max(total.get(k,0)-previous.get(k,0),0) for k in fields}
  if total is not None:turns[turn]=total
  if u is not None:usage[(sid,number)]=u
changes=collections.Counter();ids_before=[];before=collections.Counter();after=collections.Counter()
def count(e,target):
 h=e.get('harness',{}).get('name','');u=e.get('gen_ai',{}).get('usage',{})
 target[h]+=u.get('input_tokens',0)+u.get('output_tokens',0)+u.get('cache_read',{}).get('input_tokens',0)+u.get('cache_creation',{}).get('input_tokens',0)
for events in data.values():
 for e in events:
  ids_before.append(e.get('event',{}).get('id'));count(e,before)
  h=e.get('harness',{});old=h.get('name','');sid=e.get('session',{}).get('id')
  if old.startswith('codex') and sid in meta:
   m=meta[sid];origin=m.get('originator','').lower();src=m.get('source','')
   new='codex_cli' if src in ['exec','cli'] else 'codex_desktop' if origin in ['codex desktop','codex-desktop','codex-app-server','codex_app_server'] else old
   if new!=old:
    h['name']=new;changes['classification']+=1
    trace=e.get('trace',{})
    if trace.get('id')==f'session:{old}:{sid}':trace['id']=f'session:{new}:{sid}'
   raw=e.get('raw',{}).get('codex_session',{})
   if raw.get('source')=='codex_session_token_usage_record':
    u=usage.get((sid,raw.get('line')))
    if u is None:raise RuntimeError('Missing source usage for retained token event')
    corrected={'input_tokens':max(u.get('input_tokens',0)-u.get('cached_input_tokens',0)-u.get('cache_write_input_tokens',0),0),'output_tokens':u.get('output_tokens',0),'cache_read':{'input_tokens':u.get('cached_input_tokens',0)},'cache_creation':{'input_tokens':u.get('cache_write_input_tokens',0)},'reasoning':{'output_tokens':u.get('reasoning_output_tokens',0)}}
    oldusage=e.get('gen_ai',{}).get('usage',{})
    if any(oldusage.get(k)!=v for k,v in corrected.items()):
     e['gen_ai']['usage'].update(corrected);changes['token_events']+=1
  count(e,after)
assert ids_before==[e.get('event',{}).get('id') for events in data.values() for e in events]
report={'events_preserved':len(ids_before),'changes':dict(changes),'tokens_before':dict(before),'tokens_after':dict(after),'apply':args.apply}
if args.apply:
 backup=pathlib.Path.home()/'.beacon-install-backups'/('codex-repair-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'));backup.mkdir(mode=0o700)
 for f,events in data.items():
  shutil.copy2(f,backup/f.name);(backup/f.name).chmod(0o600)
  temp=f.with_name(f.name+'.repair-tmp')
  with temp.open('w') as out:
   for e in events:out.write(json.dumps(e,ensure_ascii=False,separators=(',',':'))+'\n')
   out.flush();os.fsync(out.fileno())
  temp.chmod(0o600);os.replace(temp,f)
 report['backup']=str(backup)
 (backup/'receipt.json').write_text(json.dumps(report,indent=2));(backup/'receipt.json').chmod(0o600)
print(json.dumps(report,indent=2))
