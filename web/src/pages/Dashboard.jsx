import { useCallback, useMemo } from 'preact/hooks';
import { ArrowDown, ArrowUp, HeartPulse, Cable } from 'lucide-react';
import { live, useLiveEvents, useLiveTick } from '../live.js';
import { useApi, StatusDot, Loading, PageHead, Empty } from '../components/common.jsx';
import { Chart, trafficSeries } from '../components/Chart.jsx';
import { Badge } from '../components/ui/badge';
import { Card, CardAction, CardHeader, CardTitle, CardDescription } from '../components/ui/card';
import { cn } from '../lib/utils';
import { fmtRate, fmtMs } from '../util.js';

export function Stat({ label, value, icon: Icon, className }) {
  return (
    <Card className="gap-1 p-4 sm:p-5">
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        {label}
        {Icon && <Icon className="size-4" />}
      </div>
      <div className={cn('truncate text-xl font-semibold tabular-nums sm:text-2xl', className)}>{value}</div>
    </Card>
  );
}

export function Dashboard() {
  useLiveTick('traffic');
  const [clients, cErr, , setClients] = useApi('/clients');
  const [groups, , , setGroups] = useApi('/groups');

  useLiveEvents(
    useCallback((type, d) => {
      if (type === 'ping' || type === 'status') {
        const { id, ...s } = d;
        setClients((cs) => cs && cs.map((c) => (c.id === id ? { ...c, status: { ...c.status, ...s } } : c)));
      }
      if (type === 'group') setGroups((gs) => gs && gs.map((g) => (g.id === d.id ? { ...g, current: d.current } : g)));
    }, []),
  );

  const h = live.hist;
  const data = [h.t.slice(), h.down.slice(), h.up.slice()];
  const byId = useMemo(() => Object.fromEntries((clients || []).map((c) => [c.id, c])), [clients]);

  if (!clients) return <Loading error={cErr} />;
  const enabled = clients.filter((c) => c.enabled);
  const healthy = enabled.filter((c) => c.status.state === 'up').length;
  const conns = Object.values(live.clients).reduce((a, c) => a + (c.conns || 0), 0);
  const top = enabled
    .map((c) => ({ c, r: live.clients[c.id] || { upRate: 0, downRate: 0, conns: 0 } }))
    .sort((a, b) => b.r.upRate + b.r.downRate - (a.r.upRate + a.r.downRate))
    .slice(0, 5);
  const maxRate = Math.max(1, ...top.map((x) => x.r.upRate + x.r.downRate));

  return (
    <>
      <PageHead title="Dashboard" subtitle="Live throughput and health of your proxy clients." />
      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Stat label="Download" value={fmtRate(live.total.downRate)} icon={ArrowDown} className="text-success" />
        <Stat label="Upload" value={fmtRate(live.total.upRate)} icon={ArrowUp} className="text-warning" />
        <Stat label="Healthy clients" value={`${healthy} / ${enabled.length}`} icon={HeartPulse} className={healthy < enabled.length ? 'text-warning' : 'text-success'} />
        <Stat label="Proxied connections" value={conns} icon={Cable} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Throughput</CardTitle>
          <CardDescription>last 60 seconds</CardDescription>
        </CardHeader>
        <Chart data={data} series={trafficSeries} fmt={fmtRate} />
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Groups</CardTitle>
            <CardAction><a href="#/groups" className="text-xs text-muted-foreground">Manage</a></CardAction>
          </CardHeader>
          {!groups ? <Loading /> : groups.length === 0 ? <Empty>No groups yet.</Empty> : (
            <ul className="m-0 list-none divide-y p-0">
              {groups.map((g) => {
                const cur = byId[g.current];
                return (
                  <li key={g.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 first:pt-0 last:pb-0">
                    <span className="font-medium">{g.name}</span>
                    <Badge>{g.strategy}</Badge>
                    <span className="ml-auto min-w-0 text-right text-[13px]">
                      {cur ? (
                        <a href={`#/clients/${cur.id}`} className="inline-flex items-center gap-2">
                          <StatusDot state={cur.status.state} />
                          {cur.name}
                          <span className="text-muted-foreground tabular-nums">{fmtMs(cur.status.delayMs)}</span>
                        </a>
                      ) : <span className="text-destructive">no healthy member</span>}
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top clients</CardTitle>
            <CardAction><a href="#/clients" className="text-xs text-muted-foreground">All clients</a></CardAction>
          </CardHeader>
          {top.length === 0 ? <Empty>No enabled clients.</Empty> : (
            <ul className="m-0 flex list-none flex-col gap-3.5 p-0">
              {top.map(({ c, r }) => (
                <li key={c.id} className="flex flex-col gap-1.5">
                  <div className="flex items-center gap-3 text-[13px]">
                    <a href={`#/clients/${c.id}`} className="flex min-w-0 flex-1 items-center gap-2 font-medium">
                      <StatusDot state={c.status.state} />
                      <span className="truncate">{c.name}</span>
                    </a>
                    <span className="whitespace-nowrap font-mono text-xs">
                      <span className="text-success">↓{fmtRate(r.downRate)}</span> <span className="text-warning">↑{fmtRate(r.upRate)}</span>
                    </span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-muted">
                    <div className="h-full rounded-full bg-success transition-[width] duration-500" style={{ width: ((r.upRate + r.downRate) / maxRate) * 100 + '%' }} />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
