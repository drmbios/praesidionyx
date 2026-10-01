import {test} from 'node:test';
import assert from 'node:assert/strict';
import {PolicyDemo} from '../policy.mjs';
test('injection is held for a supervisor and denial creates no file', () => {
  const p = new PolicyDemo(); p.observe();
  assert.equal(p.write().outcome,'needs_approval');
  p.decide(false); assert.equal(p.retry().outcome,'denied'); assert.deepEqual(p.files,{});
});
test('decision does not execute; exact retry is one-use and preserves taint', () => {
  const p = new PolicyDemo(); p.observe(); p.write(); const id=p.pending.id;
  p.decide(true); assert.deepEqual(p.files,{});
  assert.equal(p.retry().outcome,'allowed'); assert.equal(p.taint,'untrusted');
  assert.equal(p.write('notes.txt','Browser demonstration output',id).outcome,'denied');
});
test('changed content, context, expired approvals and narrowed scope fail', () => {
  let now=0; const p=new PolicyDemo(()=>now); p.observe(); p.write(); p.decide(true);
  assert.equal(p.write('notes.txt','different',p.pending.id).outcome,'denied');
  p.write(); p.decide(true); const id=p.pending.id; p.changeContext();
  assert.equal(p.write('notes.txt','Browser demonstration output',id).outcome,'denied');
  p.write(); p.decide(true); now=300001; assert.equal(p.retry().outcome,'denied');
  p.changeScope('reports/summary.txt'); assert.equal(p.write('notes.txt').outcome,'denied');
  p.changeScope('../escape'); assert.equal(p.write('../escape').outcome,'denied');
});
test('tool exhaustion and terminal state cannot be overridden by approval', () => {
  const p=new PolicyDemo(); p.observe(); p.write(); p.decide(true); p.budget=0;
  assert.equal(p.retry().outcome,'killed'); assert.equal(p.write().outcome,'denied');
  assert.equal(p.decide(true).outcome,'denied'); assert.deepEqual(p.files,{});
});

test('a child cannot use a broader ancestor grant to escape its floor', () => {
  const p = new PolicyDemo(); p.reset('delegation'); p.changeScope('notes.txt');
  assert.equal(p.write('notes.txt').outcome,'denied'); assert.deepEqual(p.files,{});
  p.changeScope('reports/summary.txt'); p.observe(); p.write('reports/summary.txt'); p.decide(true);
  assert.equal(p.retry().outcome,'allowed');
});
