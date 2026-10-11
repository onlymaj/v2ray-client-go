import { useEffect, useState } from 'preact/hooks';
import { RefreshCw, Trash2 } from 'lucide-react';
import { api } from '../api.js';
import { Alert, Field, SimpleSelect, Loading, PageHead, useAction, confirmDialog } from '../components/common.jsx';
import { Button } from '../components/ui/button';
import { Card, CardHeader, CardTitle } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Switch } from '../components/ui/switch';
import { navigate, uuid } from '../util.js';
import { unencrypted, UNENCRYPTED_HINT } from './Clients.jsx';

const blank = {
  name: '', enabled: true, protocol: 'vless', address: '', port: 443, uuid: '', flow: '', security: 'none',
  network: 'tcp', tls: 'reality', sni: '', fingerprint: 'chrome', alpn: [], allowInsecure: false,
  publicKey: '', shortId: '', spiderX: '', path: '', host: '', serviceName: '', multiMode: false, authority: '',
};

const VMESS_CIPHERS = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'];
const grid = 'grid grid-cols-[repeat(auto-fill,minmax(min(100%,220px),1fr))] gap-4';

const SwitchField = ({ label, hint, checked, onChange }) => (
  <Field label={label} hint={hint}>
    <div className="flex h-9 items-center"><Switch checked={checked} onCheckedChange={onChange} aria-label={label} /></div>
  </Field>
);

export function ClientEdit({ id }) {
  const [c, setC] = useState(id ? null : { ...blank, uuid: uuid() });
  const [err, setErr] = useState(null);
  const [busy, run] = useAction();

  useEffect(() => {
    // The server omits empty fields, so fill them from the blank client.
    if (id) api(`/clients/${id}`).then((x) => setC({ ...blank, ...x, alpn: x.alpn || [] }), (e) => setErr(e.message));
  }, [id]);
  if (!c) return <Loading error={err} />;

  const set = (k) => (v) => setC((x) => ({ ...x, [k]: v }));
  const inp = (k, props = {}) => <Input value={c[k]} onInput={(e) => set(k)(e.currentTarget.value)} {...props} />;

  const setProtocol = (p) =>
    setC((x) => ({
      ...x,
      protocol: p,
      security: p === 'vmess' ? (VMESS_CIPHERS.includes(x.security) ? x.security : 'auto') : 'none',
      tls: p === 'vmess' && x.tls === 'reality' ? 'tls' : x.tls,
      flow: p === 'vmess' ? '' : x.flow,
    }));

  const save = async (e) => {
    e.preventDefault();
    const { status, traffic, ...body } = { ...c, port: Number(c.port) };
    const saved = await run(() => (id ? api(`/clients/${id}`, { method: 'PUT', body }) : api('/clients', { method: 'POST', body })), 'Client saved');
    if (saved) navigate(`/clients/${saved.id}`);
  };

  const del = async () => {
    const ok = await confirmDialog({
      title: `Delete ${c.name}?`,
      description: 'The client is removed from its groups, and rules that target it are deleted. If the default rule targets it, unmatched traffic then follows the kill switch.',
      confirm: 'Delete',
      destructive: true,
    });
    if (ok && (await run(() => api(`/clients/${id}`, { method: 'DELETE' }), 'Client deleted'))) navigate('/clients');
  };

  const vless = c.protocol === 'vless';

  return (
    <form onSubmit={save} className="flex flex-col gap-6">
      <PageHead title={id ? `Edit ${c.name || 'client'}` : 'Add client'} back={id ? `#/clients/${id}` : '#/clients'} />
      {c.subscriptionId && <Alert>This client comes from a subscription. A subscription refresh may overwrite your changes, and always turns "Allow insecure" off.</Alert>}
      {c.untrusted && !c.subscriptionId && (
        <Alert>This client was imported from a link. Saving it trusts it: its server may then be a private/LAN address. Check the address first.</Alert>
      )}

      <Card>
        <CardHeader><CardTitle>General</CardTitle></CardHeader>
        <div className={grid}>
          <Field label="Name">{inp('name', { required: true, maxLength: 64 })}</Field>
          <SwitchField label="Enabled" checked={c.enabled} onChange={set('enabled')} />
          <Field label="Protocol"><SimpleSelect value={c.protocol} options={['vless', 'vmess']} onChange={setProtocol} /></Field>
          <Field label="Address" hint="Server hostname or IP">{inp('address', { required: true, autoCapitalize: 'off', spellCheck: false })}</Field>
          <Field label="Port">
            <Input type="number" min="1" max="65535" required value={c.port} onInput={(e) => set('port')(e.currentTarget.value)} />
          </Field>
          <Field label="UUID" wide>
            <div className="flex gap-2">
              {inp('uuid', { required: true, className: 'font-mono text-xs', spellCheck: false, pattern: '[0-9a-fA-F-]{32,36}' })}
              <Button type="button" variant="outline" onClick={() => set('uuid')(uuid())}><RefreshCw />Generate</Button>
            </div>
          </Field>
          {vless ? (
            <Field label="Flow" hint="Vision needs TCP with TLS or REALITY">
              <SimpleSelect value={c.flow || 'none'} options={['none', 'xtls-rprx-vision']} onChange={(v) => set('flow')(v === 'none' ? '' : v)} />
            </Field>
          ) : (
            <Field label="Security (cipher)">
              <SimpleSelect value={c.security} options={VMESS_CIPHERS} onChange={set('security')} />
            </Field>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader><CardTitle>Transport</CardTitle></CardHeader>
        <div className={grid}>
          <Field label="Network"><SimpleSelect value={c.network} options={['tcp', 'ws', 'grpc']} onChange={set('network')} /></Field>
          {c.network === 'ws' && (
            <>
              <Field label="Path">{inp('path', { placeholder: '/', className: 'font-mono text-xs' })}</Field>
              <Field label="Host header">{inp('host', { autoCapitalize: 'off' })}</Field>
            </>
          )}
          {c.network === 'grpc' && (
            <>
              <Field label="Service name">{inp('serviceName', { className: 'font-mono text-xs' })}</Field>
              <Field label="Authority">{inp('authority', { autoCapitalize: 'off' })}</Field>
              <SwitchField label="Multi mode" checked={c.multiMode} onChange={set('multiMode')} />
            </>
          )}
        </div>
      </Card>

      <Card>
        <CardHeader><CardTitle>TLS</CardTitle></CardHeader>
        <div className={grid}>
          <Field label="Security">
            <SimpleSelect value={c.tls} options={vless ? ['none', 'tls', 'reality'] : ['none', 'tls']} onChange={set('tls')} />
          </Field>
          {unencrypted(c) && <Alert variant="destructive" className="sm:col-span-2"><b>Unencrypted.</b> {UNENCRYPTED_HINT}</Alert>}
          {c.tls !== 'none' && (
            <>
              <Field label="SNI">{inp('sni', { autoCapitalize: 'off', spellCheck: false })}</Field>
              <Field label="Fingerprint">
                <SimpleSelect value={c.fingerprint || 'chrome'} options={['chrome', 'firefox', 'safari', 'random']} onChange={set('fingerprint')} />
              </Field>
            </>
          )}
          {c.tls === 'tls' && (
            <>
              <Field label="ALPN" hint="Comma separated, e.g. h2,http/1.1">
                <Input value={c.alpn.join(',')} onInput={(e) => set('alpn')(e.currentTarget.value.split(',').map((s) => s.trim()).filter(Boolean))} />
              </Field>
              <SwitchField label="Allow insecure" hint="Skips certificate verification: anyone on the network path can intercept the connection and read the traffic. Links and subscriptions never set this." checked={c.allowInsecure} onChange={set('allowInsecure')} />
            </>
          )}
          {c.tls === 'reality' && (
            <>
              <Field label="Public key" wide>{inp('publicKey', { required: true, className: 'font-mono text-xs', spellCheck: false })}</Field>
              <Field label="Short ID">{inp('shortId', { className: 'font-mono text-xs', spellCheck: false, pattern: '[0-9a-fA-F]{0,16}' })}</Field>
              <Field label="SpiderX">{inp('spiderX', { className: 'font-mono text-xs', placeholder: '/' })}</Field>
            </>
          )}
        </div>
      </Card>

      <div className="flex flex-wrap items-center gap-2">
        {id && <Button type="button" variant="outline" className="text-destructive" onClick={del} disabled={busy}><Trash2 />Delete</Button>}
        <span className="flex-1" />
        <Button asChild variant="ghost"><a href={id ? `#/clients/${id}` : '#/clients'}>Cancel</a></Button>
        <Button type="submit" disabled={busy}>{busy ? 'Saving...' : 'Save'}</Button>
      </div>
    </form>
  );
}
