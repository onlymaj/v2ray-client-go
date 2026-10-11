import { useEffect, useRef, useState } from 'preact/hooks';
import { GripVertical, Plus, Save, X } from 'lucide-react';
import { api } from '../api.js';
import { useApi, Field, SimpleSelect, Loading, PageHead, Alert, Empty, useAction } from '../components/common.jsx';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Textarea } from '../components/ui/textarea';
import { cn } from '../lib/utils';

const TYPES = [
  ['source', 'Source IP'],
  ['domain', 'Domain'],
  ['dest', 'Destination'],
  ['default', 'Default'],
];
const KINDS = [
  ['group', 'Group'],
  ['client', 'Client'],
  ['direct', 'Direct'],
  ['block', 'Block'],
];
const PLACEHOLDER = {
  source: '192.168.88.10\n192.168.88.32/28',
  domain: 'netflix.com  (also matches subdomains)\nir',
  dest: '10.0.0.0/8\n1.1.1.1',
};

let keySeq = 0;
const toLocal = (r) => ({ ...r, values: r.values || [], _k: ++keySeq, _text: (r.values || []).join('\n') });
const toApi = ({ _k, _text, ...r }) => ({
  ...r,
  values: r.type === 'default' ? [] : _text.split('\n').map((s) => s.trim()).filter(Boolean),
  target: { kind: r.target.kind, id: r.target.kind === 'client' || r.target.kind === 'group' ? r.target.id : '' },
});
const normalize = (rules) => rules.map((r) => toApi(toLocal(r)));

export function Rules() {
  const [saved, err, , setSaved] = useApi('/rules');
  const [clients] = useApi('/clients');
  const [groups] = useApi('/groups');
  const [rules, setRules] = useState(null);
  const [dragKey, setDragKey] = useState(null);
  const [busy, run] = useAction();
  const listRef = useRef(null);

  useEffect(() => {
    if (saved) setRules(saved.map(toLocal));
  }, [saved]);

  if (!rules || !clients || !groups) return <Loading error={err} />;

  const dirty = JSON.stringify(rules.map(toApi)) !== JSON.stringify(normalize(saved));
  const update = (k, patch) => setRules((rs) => rs.map((r) => (r._k === k ? { ...r, ...patch } : r)));
  const moveTo = (from, to) =>
    setRules((rs) => {
      if (to < 0 || to >= rs.length || from === to) return rs;
      const next = [...rs];
      next.splice(to, 0, next.splice(from, 1)[0]);
      return next;
    });

  // Drag by the handle with pointer events (mouse, pen and touch). Listeners go
  // on window because the dragged row moves in the DOM while dragging.
  const startDrag = (e, key) => {
    if (e.button !== 0) return;
    e.preventDefault();
    setDragKey(key);
    const onMove = (ev) => {
      const rows = [...listRef.current.children];
      setRules((rs) => {
        const from = rs.findIndex((r) => r._k === key);
        let to = 0;
        rows.forEach((row, i) => {
          if (i === from) return;
          const b = row.getBoundingClientRect();
          if (ev.clientY > b.top + b.height / 2) to++;
        });
        if (to === from) return rs;
        const next = [...rs];
        next.splice(to, 0, next.splice(from, 1)[0]);
        return next;
      });
    };
    const onUp = () => {
      setDragKey(null);
      removeEventListener('pointermove', onMove);
      removeEventListener('pointerup', onUp);
      removeEventListener('pointercancel', onUp);
    };
    addEventListener('pointermove', onMove);
    addEventListener('pointerup', onUp);
    addEventListener('pointercancel', onUp);
  };

  const add = () =>
    setRules((rs) => {
      const r = toLocal({ type: 'domain', values: [], target: { kind: 'group', id: groups[0]?.id || '' } });
      const d = rs.findIndex((x) => x.type === 'default');
      return d < 0 ? [...rs, r] : [...rs.slice(0, d), r, ...rs.slice(d)];
    });

  const save = async () => {
    const out = await run(() => api('/rules', { method: 'PUT', body: rules.map(toApi) }), 'Rules saved');
    if (out) setSaved(out);
  };

  const defaultIdx = rules.findIndex((r) => r.type === 'default');
  const targetOptions = (kind) => (kind === 'client' ? clients : kind === 'group' ? groups : []).map((x) => [x.id, x.name]);

  return (
    <>
      <PageHead title="Rules" subtitle="Checked top to bottom; the first match decides where a connection goes. Drag the handle to reorder.">
        <Button variant="outline" onClick={add}><Plus />Add rule</Button>
        <Button onClick={save} disabled={busy || !dirty}><Save />{busy ? 'Saving...' : 'Save'}</Button>
      </PageHead>
      {dirty && <Alert>Unsaved changes.</Alert>}
      {defaultIdx >= 0 && defaultIdx < rules.length - 1 && <Alert variant="destructive">Rules below the default rule never match.</Alert>}
      {defaultIdx < 0 && <Alert>No default rule: unmatched traffic follows the kill switch setting.</Alert>}

      <ol className="m-0 flex list-none flex-col gap-2 p-0" ref={listRef}>
        {rules.map((r, i) => (
          <li key={r._k}>
            <Card
              className={cn(
                'flex-row gap-0 overflow-hidden p-0 sm:p-0',
                dragKey === r._k && 'relative z-10 border-border-strong shadow-lg ring-2 ring-ring/30',
                defaultIdx >= 0 && i > defaultIdx && 'opacity-55',
              )}
            >
              <button
                type="button"
                className={cn(
                  'flex w-10 shrink-0 cursor-grab touch-none select-none flex-col items-center justify-center gap-1 border-r bg-muted text-muted-foreground focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-inset focus-visible:ring-ring/50',
                  dragKey === r._k && 'cursor-grabbing text-foreground',
                )}
                aria-label={`Move rule ${i + 1} (arrow keys)`}
                onPointerDown={(e) => startDrag(e, r._k)}
                onKeyDown={(e) => {
                  if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
                    e.preventDefault();
                    moveTo(i, i + (e.key === 'ArrowUp' ? -1 : 1));
                  }
                }}
              >
                <span className="text-xs font-semibold">{i + 1}</span>
                <GripVertical className="size-4" />
              </button>
              <div className="flex min-w-0 flex-1 flex-col gap-3 p-3 sm:p-4">
                <div className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] items-end gap-2 sm:grid-cols-[repeat(3,minmax(0,1fr))_auto] sm:gap-3">
                  <Field label="Match">
                    <SimpleSelect value={r.type} options={TYPES} onChange={(v) => update(r._k, { type: v })} />
                  </Field>
                  <Field label="Send to">
                    <SimpleSelect value={r.target.kind} options={KINDS} onChange={(kind) => update(r._k, { target: { kind, id: targetOptions(kind)[0]?.[0] || '' } })} />
                  </Field>
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon-sm"
                    className="col-start-3 row-start-1 self-start text-destructive sm:col-start-4"
                    onClick={() => setRules((rs) => rs.filter((x) => x._k !== r._k))}
                    aria-label="Delete rule"
                  >
                    <X />
                  </Button>
                  {(r.target.kind === 'client' || r.target.kind === 'group') && (
                    <Field label={r.target.kind === 'client' ? 'Client' : 'Group'} className="col-span-2 sm:col-span-1 sm:col-start-3 sm:row-start-1">
                      <SimpleSelect value={r.target.id} options={targetOptions(r.target.kind)} onChange={(id) => update(r._k, { target: { ...r.target, id } })} />
                    </Field>
                  )}
                </div>
                {r.type !== 'default' && (
                  <Textarea
                    className="font-mono text-xs"
                    rows={Math.min(6, Math.max(2, r._text.split('\n').length))}
                    spellCheck={false}
                    placeholder={PLACEHOLDER[r.type]}
                    value={r._text}
                    onInput={(e) => update(r._k, { _text: e.currentTarget.value })}
                  />
                )}
              </div>
            </Card>
          </li>
        ))}
      </ol>
      {rules.length === 0 && <Card><Empty>No rules. Add one, or all traffic follows the kill switch setting.</Empty></Card>}
    </>
  );
}
