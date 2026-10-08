import { useCallback, useEffect, useMemo, useState } from 'preact/hooks';
import { Pencil, Stethoscope } from 'lucide-react';
import { api } from '../api.js';
import { live, useLiveEvents, useLiveTick } from '../live.js';
import { useApi, StatusDot, Loading, PageHead, CopyField, Alert, toast } from '../components/common.jsx';
import { Chart, trafficSeries } from '../components/Chart.jsx';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Card, CardAction, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { Switch } from '../components/ui/switch';
import { Tabs, TabsList, TabsTrigger } from '../components/ui/tabs';
import { fmtRate, fmtMs, fmtAgo, fmtBytes } from '../util.js';
import { transport, TrustBadges, untrustedHint } from './Clients.jsx';
import { Stat } from './Dashboard.jsx';

const delaySeries = [{ label: 'Delay', color: '--info' }];
const STATE_CLASS = { up: 'text-success', down: 'text-destructive', unknown: 'text-warning', disabled: 'text-muted-foreground' };

export function ClientDetail({ id }) {
  useLiveTick('traffic');
  const [c, err, , setC] = useApi(`/clients/${id}`);
  const [range, setRange] = useState('1h');
  const [stats] = useApi(`/stats?target=client:${id}&range=${range}`);
  const [link, setLink] = useState('');

  useEffect(() => {
    api(`/clients/${id}/link`).then((r) => setLink(r.link), () => {});
  }, [id, c?.uuid, c?.address, c?.port]);

  useLiveEvents(
    useCallback(
      (type, d) => {
        if ((type !== 'ping' && type !== 'status') || d.id !== id) return;
        const { id: _, ...s } = d;
        const now = new Date().toISOString();
        setC((x) => x && { ...x, status: { ...x.status, ...s, ...(type === 'ping' ? { lastCheck: now, ...(s.state === 'up' && { lastSuccess: now }) } : {}) } });
      },
      [id],
    ),
  );

  const tData = useMemo(() => stats && [stats.t, stats.down, stats.up], [stats]);
  const dData = useMemo(() => stats && [stats.t, stats.delay], [stats]);

  if (!c) return <Loading error={err} />;
  const r = live.clients[id] || c.traffic;
  const st = c.enabled ? c.status.state : 'disabled';

  const toggle = async () => {
    try {
      setC(await api(`/clients/${id}/toggle`, { method: 'POST' }));
    } catch (e) {
      toast(e.message, 'err');
    }
  };
  const check = () => api(`/clients/${id}/check`, { method: 'POST' }).then(() => toast('Health check started'), (e) => toast(e.message, 'err'));

  return (
    <>
      <PageHead title={<><StatusDot state={st} className="size-2.5" /><span className="truncate">{c.name}</span></>} back="#/clients">
        <Switch checked={c.enabled} onCheckedChange={toggle} aria-label="Enabled" />
        <Button variant="outline" onClick={check} disabled={!c.enabled}><Stethoscope />Check now</Button>
        <Button asChild variant="outline"><a href={`#/clients/${id}/edit`}><Pencil />Edit</a></Button>
      </PageHead>

      <div className="grid grid-cols-2 gap-3 sm:gap-4 xl:grid-cols-4">
        <Stat label="State" value={st} className={STATE_CLASS[st]} />
        <Stat label="Delay / TCP" value={<>{fmtMs(c.status.delayMs)} <span className="text-sm text-muted-foreground">{fmtMs(c.status.tcpMs)}</span></>} />
        <Stat label="Download" value={fmtRate(r.downRate)} className="text-success" />
        <Stat label="Upload" value={fmtRate(r.upRate)} className="text-warning" />
      </div>

      {c.tls === 'tls' && c.allowInsecure && (
        <Alert variant="destructive"><b>Certificate verification is off.</b> Anyone on the network path can intercept this connection and read the traffic. Turn off "Allow insecure" in the editor unless you trust every network in between.</Alert>
      )}
      {c.untrusted && (
        <Alert><b>Untrusted.</b> {untrustedHint(c)}</Alert>
      )}

      {c.status.lastError && st !== 'up' && (
        <Alert variant="destructive"><b>Last error:</b> <span className="font-mono text-xs">{c.status.lastError}</span></Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle>Traffic</CardTitle>
          <CardAction>
            <Tabs value={range} onValueChange={setRange}>
              <TabsList>
                <TabsTrigger value="1h">1h</TabsTrigger>
                <TabsTrigger value="24h">24h</TabsTrigger>
              </TabsList>
            </Tabs>
          </CardAction>
        </CardHeader>
        {tData ? <Chart data={tData} series={trafficSeries} fmt={fmtRate} /> : <Loading />}
        <CardTitle className="mt-2">Latency</CardTitle>
        {dData ? <Chart data={dData} series={delaySeries} fmt={fmtMs} height={160} /> : <Loading />}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader><CardTitle>Details</CardTitle></CardHeader>
          <dl className="m-0 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-[13px] [&_dd]:m-0 [&_dd]:min-w-0 [&_dd]:[overflow-wrap:anywhere] [&_dt]:text-muted-foreground">
            <dt>Transport</dt><dd className="flex flex-wrap gap-1"><Badge>{transport(c)}</Badge><TrustBadges c={c} /></dd>
            <dt>Server</dt><dd className="font-mono text-xs text-info">{c.address}:{c.port}</dd>
            {c.sni && <><dt>SNI</dt><dd className="font-mono text-xs text-info">{c.sni}</dd></>}
            <dt>Last success</dt><dd>{fmtAgo(c.status.lastSuccess)}</dd>
            <dt>Last check</dt><dd>{fmtAgo(c.status.lastCheck)}</dd>
            <dt>Connections</dt><dd>{r.conns ?? 0}</dd>
            <dt>Total</dt><dd><span className="text-success">↓{fmtBytes(c.traffic.down)}</span> <span className="text-warning">↑{fmtBytes(c.traffic.up)}</span></dd>
            {c.subscriptionId && <><dt>Source</dt><dd><a href="#/clients/import" className="underline">subscription</a></dd></>}
          </dl>
        </Card>
        <Card>
          <CardHeader className="flex-col items-start gap-1">
            <CardTitle>Share link</CardTitle>
            <CardDescription>Contains the UUID and keys. Share it only with people who should use this server.</CardDescription>
          </CardHeader>
          {link ? <CopyField value={link} /> : <Loading />}
        </Card>
      </div>
    </>
  );
}
