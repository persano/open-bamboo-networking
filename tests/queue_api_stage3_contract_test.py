"""Offline schema/fixture tests only. No native calls and no printer operations."""
import copy
import json
from pathlib import Path
import unittest
from datetime import datetime
import re

from jsonschema import Draft202012Validator, FormatChecker

FORMATS = FormatChecker()
@FORMATS.checks('date-time', raises=ValueError)
def utc_timestamp(value):
    # This contract requires UTC Z timestamps; no optional format packages needed.
    if not isinstance(value,str): return True
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z',value): return False
    datetime.fromisoformat(value)
    return True

BASE = Path(__file__).resolve().parents[1] / 'docs/queue-api-v1-stage3'
def read(name): return json.loads((BASE/name).read_text(encoding='utf-8'))

class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schemas={p.name: json.loads(p.read_text(encoding='utf-8')) for p in BASE.glob('*.schema.json')}
        cls.validators={name:Draft202012Validator(s,format_checker=FORMATS) for name,s in cls.schemas.items()}
        cls.examples=read('examples.json')
        cls.events=read('event-examples.json')

    def test_all_schemas_well_formed(self):
        for name,s in self.schemas.items():
            with self.subTest(name=name): Draft202012Validator.check_schema(s)

    def test_examples_and_events(self):
        for e in self.examples:
            with self.subTest(name=e['name']):
                self.validators['request.schema.json'].validate(e['request'])
                self.validators['response.schema.json'].validate(e['response'])
                self.assertEqual(e['request']['request_id'],e['response']['request_id'])
                self.assertEqual(e['request']['op'],e['response']['op'])
                if e['response']['ok'] and e['request']['op']=='command.submit':
                    p,r=e['request']['params'],e['response']['result']
                    self.assertEqual((p['submission_scope'],p['idempotency_key'],p['command']['device_id'],p['command']['kind']),
                                     (r['submission_scope'],r['idempotency_key'],r['device_id'],r['kind']))
                    if 'expected_job_id' in p['command']:
                        self.assertEqual(p['command']['expected_job_id'],r['job_id'])
        for e in self.events:
            self.validators['event.schema.json'].validate(e)
            body=e['data'].get('job',e['data'].get('receipt'))
            self.assertEqual(e['data']['device_id'],body['device_id'])

    def test_request_rejections(self):
        source=self.examples[0]['request']
        cases=[]
        for field in ('idempotency_key','submission_scope'):
            bad=copy.deepcopy(source);del bad['params'][field];cases.append((field,bad))
        bad=copy.deepcopy(source);bad['params']['idempotency_key']='';cases.append(('empty-key',bad))
        bad=copy.deepcopy(source);bad['params']['command']['payload']['materials']=[];cases.append(('missing-materials',bad))
        bad=copy.deepcopy(source);bad['params']['command']['payload']['supply']='auto';cases.append(('implicit-supply',bad))
        bad=copy.deepcopy(source);bad['params']['command']['payload']['file']['sha256']='bad';cases.append(('hash',bad))
        bad=copy.deepcopy(source);bad['params']['command']['payload']['file']['plate_index']=0;cases.append(('plate-zero',bad))
        bad=copy.deepcopy(source);bad['access_token']='synthetic';cases.append(('credential',bad))
        bad=copy.deepcopy(source);bad['params']['command']['payload']['options']['unknown']=True;cases.append(('option',bad))
        bad=copy.deepcopy(source);bad['api']=2;cases.append(('api',bad))
        pause=next(e['request'] for e in self.examples if e['name']=='pause')
        bad=copy.deepcopy(pause);del bad['params']['command']['expected_job_id'];cases.append(('unbound-control',bad))
        motion=next(e['request'] for e in self.examples if e['name']=='mechanical-ordinary-print')
        bad=copy.deepcopy(motion);bad['params']['command']['payload']['options']['flow_calibration']=True;cases.append(('mechanical-calibration',bad))
        skip=next(e['request'] for e in self.examples if e['name']=='skip_objects')
        bad=copy.deepcopy(skip);bad['params']['command']['object_ids']=['x','x'];cases.append(('duplicate-objects',bad))
        for name,bad in cases:
            with self.subTest(name=name): self.assertFalse(self.validators['request.schema.json'].is_valid(bad))

    def test_terminal_evidence_rejections(self):
        source=next(e['response'] for e in self.examples if e['name']=='job-terminal-lookup')
        cases=[]
        for field in ('state','error_code','observed_at','source','correlation','connection_generation','quiescent'):
            bad=copy.deepcopy(source);del bad['result']['job']['terminal'][field];cases.append((field,bad))
        bad=copy.deepcopy(source);bad['result']['job']['terminal']['observed_at']='yesterday';cases.append(('timestamp',bad))
        bad=copy.deepcopy(source);bad['result']['job']['terminal']['observed_at']='2026-02-30T10:00:00Z';cases.append(('calendar-date',bad))
        bad=copy.deepcopy(source);bad['result']['job']['terminal']['state']='failed';cases.append(('conflicting-state',bad))
        bad=copy.deepcopy(source);bad['result']['job']['terminal']=None;cases.append(('missing-terminal',bad))
        bad=copy.deepcopy(source);bad['result']['job']['state']='printing';cases.append(('nonterminal-with-terminal',bad))
        for name,bad in cases:
            with self.subTest(name=name): self.assertFalse(self.validators['response.schema.json'].is_valid(bad))

    def test_ack_is_not_completion_and_retry_identity_is_stable_in_examples(self):
        a,b=self.examples[:2]
        self.assertNotEqual(a['request']['request_id'],b['request']['request_id'])
        self.assertEqual(a['response']['result'],b['response']['result'])
        accepted=a['response']['result']
        ack=next(e['response']['result'] for e in self.examples if e['name']=='recover-receipt')
        done=next(e['response']['result']['job'] for e in self.examples if e['name']=='job-terminal-lookup')
        self.assertEqual(accepted['job_id'],ack['job_id'])
        self.assertEqual(ack['job_id'],done['job_id'])
        self.assertEqual(accepted['state'],'accepted')
        self.assertEqual(ack['state'],'succeeded')
        self.assertNotIn('terminal',ack)
        self.assertEqual(done['state'],'completed')

    def test_receipt_requires_identity_and_confirmed_success(self):
        source=next(e['response'] for e in self.examples if e['name']=='recover-receipt')
        for field in ('job_id','command_id','idempotency_key','submission_scope'):
            bad=copy.deepcopy(source);del bad['result'][field]
            with self.subTest(field=field):self.assertFalse(self.validators['response.schema.json'].is_valid(bad))
        bad=copy.deepcopy(source);bad['result']['dispatch']='may_have_been_sent'
        self.assertFalse(self.validators['response.schema.json'].is_valid(bad))

    def test_additive_response_fields_and_unknown_evidence_are_preserved(self):
        good=copy.deepcopy(self.examples[0]['response']);good['future_field']={'x':1}
        self.validators['response.schema.json'].validate(good)
        done=copy.deepcopy(next(e['response'] for e in self.examples if e['name']=='job-terminal-lookup'))
        done['result']['job']['terminal'].update(error_code=None,source='unknown',correlation='unverified',quiescent=False)
        self.validators['response.schema.json'].validate(done)
        # Structurally valid does NOT mean it can authorize a plate swap.

    def test_capability_fragments(self):
        self.validators['capability-additions.schema.json'].validate(dict(command_protocol_revision='stage3-draft-1',
            submission=dict(scope='scope-A',idempotency='durable_at_most_once_dispatch',receipt_retention='until_explicit_store_reset',
                            max_retained_keys=4096,max_pending_per_device=1)))
        self.validators['printer-additions.schema.json'].validate(dict(nozzle_diameter=None,
            command_support=dict(command_kinds=['print'],print_options=['bed_leveling'],supply_modes=['ams','external'])))

if __name__=='__main__': unittest.main(verbosity=2)
