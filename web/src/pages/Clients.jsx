import { useCallback } from 'preact/hooks';
import { Plus, Upload, Pencil } from 'lucide-react';
import { api } from '../api.js';
import { live, useLiveEvents, useLiveTick } from '../live.js';
import { useApi, StatusDot, Loading, PageHead, Empty, toast } from '../components/common.jsx';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../components/ui/table';
import { cn } from '../lib/utils';
import { fmtRate, fmtMs } from '../util.js';

/** Short transport description, e.g. "vless · ws · tls". */
export const transport = (c) => [c.protocol, c.network, c.tls !== 'none' && c.tls, c.flow && 'vision'].filter(Boolean).join(' · ');

/** Patches a client list from ping/status SSE events. */
export function useClientStatus(setClients) {
  useLiveEvents(
    useCallback((type, d) => {
      if (type !== 'ping' && type !== 'status') return;
      const { id, ...s } = d;
      setClients((cs) => cs && cs.map((c) => (c.id === id ? { ...c, status: { ...c.status, ...s } } : c)));
    }, []),
  );
}

export function Clients() {
  useLiveTick('traffic');
  const [clients, err, , setClients] = useApi('/clients');
  useClientStatus(setClients);

  const toggle = async (c) => {
    try {
      const u = await api(`/clients/${c.id}/toggle`, { method: 'POST' });
      setClients((cs) => cs.map((x) => (x.id === c.id ? u : x)));
    } catch (e) {
      toast(e.message, 'err');
    }
  };

  return (
    <>
      <PageHead title="Clients" subtitle="VLESS and VMess servers the router can send traffic through.">
        <Button asChild variant="outline"><a href="#/clients/import"><Upload />Import</a></Button>
        <Button asChild><a href="#/clients/new"><Plus />Add client</a></Button>
      </PageHead>
      {!clients ? <Loading error={err} /> : clients.length === 0 ? (
        <Card><Empty>No clients yet. <a href="#/clients/import" className="underline">Import share links</a> or <a href="#/clients/new" className="underline">add one manually</a>.</Empty></Card>
      ) : (
        <Card className="gap-0 overflow-hidden p-0 sm:p-0">
          <Table cards>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Transport</TableHead>
                <TableHead className="text-right">Latency</TableHead>
                <TableHead className="text-right">Down</TableHead>
                <TableHead className="text-right">Up</TableHead>
                <TableHead className="text-right">Conns</TableHead>
                <TableHead>Enabled</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {clients.map((c) => {
                const r = live.clients[c.id] || c.traffic;
                const st = c.enabled ? c.status.state : 'disabled';
                return (
                  <TableRow key={c.id} className={cn(!c.enabled && 'opacity-60')}>
                    <TableCell className="cell-title max-w-[260px]">
                      <a href={`#/clients/${c.id}`} className="flex items-center gap-2.5 font-medium">
                        <StatusDot state={st} />
                        <span className="truncate">{c.name}</span>
                      </a>
                      <div className="truncate pl-[18px] font-mono text-xs font-normal text-muted-foreground">{c.address}:{c.port}</div>
                      {st === 'down' && c.status.lastError && (
                        <div className="truncate pl-[18px] text-xs font-normal text-destructive" title={c.status.lastError}>{c.status.lastError}</div>
                      )}
                    </TableCell>
                    <TableCell className="cell-wide"><Badge>{transport(c)}</Badge></TableCell>
                    <TableCell data-label="Latency" className="text-right whitespace-nowrap">{st === 'up' ? fmtMs(c.status.delayMs) : '-'}</TableCell>
                    <TableCell data-label="Down" className="text-right whitespace-nowrap text-success">{fmtRate(r.downRate)}</TableCell>
                    <TableCell data-label="Up" className="text-right whitespace-nowrap text-warning">{fmtRate(r.upRate)}</TableCell>
                    <TableCell data-label="Conns" className="text-right max-md:hidden">{r.conns ?? 0}</TableCell>
                    <TableCell className="cell-actions">
                      <div className="flex items-center gap-1">
                        <Switch checked={c.enabled} aria-label={`Enable ${c.name}`} onCheckedChange={() => toggle(c)} />
                        <Button asChild variant="ghost" size="icon-sm" className="ml-1">
                          <a href={`#/clients/${c.id}/edit`} aria-label={`Edit ${c.name}`}><Pencil /></a>
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </Card>
      )}
    </>
  );
}
