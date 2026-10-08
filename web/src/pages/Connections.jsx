import { useEffect, useState } from 'preact/hooks';
import { Pause, Play, Search } from 'lucide-react';
import { api } from '../api.js';
import { useApi, Loading, PageHead, Alert, Empty } from '../components/common.jsx';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table';
import { fmtBytes, fmtDuration, since } from '../util.js';

export function Connections() {
  const [conns, setConns] = useState(null);
  const [err, setErr] = useState(null);
  const [q, setQ] = useState('');
  const [paused, setPaused] = useState(false);
  // Connections carry ids; names come from these lists.
  const [clients, , reloadClients] = useApi('/clients');
  const [groups, , reloadGroups] = useApi('/groups');
  const [rules, , reloadRules] = useApi('/rules');

  useEffect(() => {
    if (paused) return;
    let alive = true;
    const load = () =>
      api('/connections').then(
        (c) => alive && (setConns(c), setErr(null)),
        (e) => alive && setErr(e.message),
      );
    load();
    const t = setInterval(load, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [paused]);

  // Refetch the lookups when a connection references an id we do not know yet.
  const clientName = Object.fromEntries((clients || []).map((c) => [c.id, c.name]));
  const groupName = Object.fromEntries((groups || []).map((g) => [g.id, g.name]));
  const ruleLabel = Object.fromEntries((rules || []).map((r, i) => [r.id, `#${i + 1} ${r.type}${r.values?.[0] ? ' ' + r.values[0] : ''}`]));
  const unknown = (conns || []).some(
    (c) => (c.client && c.client !== 'direct' && !(c.client in clientName)) || (c.group && !(c.group in groupName)) || (c.rule && !(c.rule in ruleLabel)),
  );
  useEffect(() => {
    if (!unknown || !clients || !groups || !rules) return;
    const t = setTimeout(() => (reloadClients(), reloadGroups(), reloadRules()), 3000);
    return () => clearTimeout(t);
  }, [unknown, clients, groups, rules]);

  if (!conns || !clients || !groups || !rules) return <Loading error={err} />;
  const view = conns.map((c) => ({
    ...c,
    ruleText: c.rule ? ruleLabel[c.rule] || c.rule : 'kill switch',
    clientText: c.client === 'direct' ? 'direct' : c.client ? clientName[c.client] || c.client : 'blocked',
    groupText: c.group ? groupName[c.group] || c.group : '',
  }));
  const needle = q.trim().toLowerCase();
  const rows = view
    .filter((c) => !needle || [c.src, c.dst, c.domain, c.ruleText, c.clientText, c.groupText].some((v) => v && v.toLowerCase().includes(needle)))
    .sort((a, b) => Date.parse(b.start) - Date.parse(a.start));

  return (
    <>
      <PageHead title="Connections" subtitle="Open connections from the LAN, refreshed every 2 seconds.">
        <Button variant="outline" onClick={() => setPaused(!paused)}>{paused ? <Play /> : <Pause />}{paused ? 'Resume' : 'Pause'}</Button>
      </PageHead>
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input type="search" className="pl-9" placeholder="Filter by IP, domain, rule or client" value={q} onInput={(e) => setQ(e.currentTarget.value)} />
        </div>
        <span className="whitespace-nowrap text-xs text-muted-foreground">{rows.length} of {conns.length}</span>
      </div>
      {err && <Alert variant="destructive">{err}</Alert>}
      <Card className="gap-0 overflow-hidden p-0 sm:p-0">
        <Table cards>
          <TableHeader>
            <TableRow>
              <TableHead>Source</TableHead>
              <TableHead>Destination</TableHead>
              <TableHead>Rule</TableHead>
              <TableHead>Client</TableHead>
              <TableHead className="text-right">Down</TableHead>
              <TableHead className="text-right">Up</TableHead>
              <TableHead className="text-right">Age</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((c) => (
              <TableRow key={c.id}>
                <TableCell data-label="Source" className="font-mono text-xs">{c.src}</TableCell>
                <TableCell className="cell-title max-w-[280px] truncate" title={c.dst}>
                  {c.domain ? (
                    <>{c.domain}<span className="font-mono text-xs font-normal text-muted-foreground">:{c.dst.split(':').pop()}</span></>
                  ) : <span className="font-mono text-xs">{c.dst}</span>}
                </TableCell>
                <TableCell data-label="Rule" className="text-xs">{c.ruleText}</TableCell>
                <TableCell data-label="Client">
                  {c.client === 'direct' ? <Badge>direct</Badge> : !c.client ? <Badge variant="destructive">blocked</Badge> : (
                    <a href={`#/clients/${c.client}`}>{c.clientText}</a>
                  )}
                  {c.groupText && <span className="text-xs text-muted-foreground"> via {c.groupText}</span>}
                </TableCell>
                <TableCell data-label="Down" className="text-right whitespace-nowrap text-success">{fmtBytes(c.down)}</TableCell>
                <TableCell data-label="Up" className="text-right whitespace-nowrap text-warning">{fmtBytes(c.up)}</TableCell>
                <TableCell data-label="Age" className="text-right whitespace-nowrap">{fmtDuration(since(c.start))}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {rows.length === 0 && <Empty>No connections{needle && ' match the filter'}.</Empty>}
      </Card>
    </>
  );
}
