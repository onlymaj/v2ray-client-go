import { useCallback, useEffect, useState } from 'preact/hooks';
import { CircleAlert, Info, Copy, Check, ArrowLeft } from 'lucide-react';
import { api } from '../api.js';
import { copyText } from '../util.js';
import { cn } from '@/lib/utils';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from './ui/dialog';

/** Loads an API path; returns [data, error, reload, setData]. */
export function useApi(path) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const load = useCallback(() => {
    if (!path) return Promise.resolve();
    return api(path).then(
      (d) => (setData(d), setError(null)),
      (e) => setError(e.message),
    );
  }, [path]);
  useEffect(() => {
    load();
  }, [load]);
  return [data, error, load, setData];
}

// ---------- toasts ----------

let pushToast = () => {};
/** @param {string} msg @param {'ok'|'err'} [kind] */
export const toast = (msg, kind = 'ok') => pushToast(msg, kind);

export function Toasts() {
  const [items, setItems] = useState([]);
  pushToast = (msg, kind) => {
    const id = Math.random();
    setItems((x) => [...x, { id, msg, kind }]);
    setTimeout(() => setItems((x) => x.filter((i) => i.id !== id)), kind === 'err' ? 6000 : 2500);
  };
  return (
    <div className="pointer-events-none fixed inset-x-4 bottom-4 z-[60] flex flex-col items-end gap-2" role="status">
      {items.map((t) => (
        <div
          key={t.id}
          className={cn(
            'pointer-events-auto flex max-w-sm items-start gap-2 rounded-md border bg-popover px-4 py-3 text-sm shadow-lg animate-in fade-in-0 slide-in-from-bottom-2',
            t.kind === 'err' && 'border-destructive/40 text-destructive',
          )}
        >
          {t.kind === 'err' ? <CircleAlert className="mt-0.5 size-4 shrink-0" /> : <Check className="mt-0.5 size-4 shrink-0 text-success" />}
          <span className="break-words [overflow-wrap:anywhere]">{t.msg}</span>
        </div>
      ))}
    </div>
  );
}

// ---------- confirm dialog ----------

let openConfirm = () => Promise.resolve(false);
/** Promise-based replacement for window.confirm. */
export const confirmDialog = (opts) => openConfirm(opts);

export function ConfirmHost() {
  const [state, setState] = useState(null);
  openConfirm = (opts) => new Promise((resolve) => setState({ ...opts, resolve }));
  const close = (v) => {
    state?.resolve(v);
    setState(null);
  };
  return (
    <Dialog open={!!state} onOpenChange={(o) => !o && close(false)}>
      {state && (
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{state.title}</DialogTitle>
            {state.description && <DialogDescription>{state.description}</DialogDescription>}
          </DialogHeader>
          <DialogFooter>
            <Button variant="ghost" onClick={() => close(false)}>Cancel</Button>
            <Button variant={state.destructive ? 'destructive' : 'default'} onClick={() => close(true)}>{state.confirm || 'Confirm'}</Button>
          </DialogFooter>
        </DialogContent>
      )}
    </Dialog>
  );
}

// ---------- small pieces ----------

const DOT = {
  up: 'bg-success',
  down: 'bg-destructive',
  unknown: 'bg-warning',
  disabled: 'border-2 border-muted-foreground bg-transparent',
};
export const StatusDot = ({ state, className }) => (
  <span
    title={state}
    className={cn('inline-block size-2 shrink-0 rounded-full shadow-[0_0_0_3px_rgba(255,255,255,0.04)]', DOT[state] || 'bg-muted-foreground', className)}
  />
);

export function Field({ label, hint, children, wide, className }) {
  return (
    <div className={cn('flex min-w-0 flex-col gap-1.5', wide && 'col-span-full', className)}>
      <Label>{label}</Label>
      {children}
      {hint && <p className="m-0 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/** shadcn Select from a list of values or [value, label] pairs. Values must be non-empty strings. */
export function SimpleSelect({ value, options, onChange, placeholder, className, size, ...rest }) {
  return (
    <Select value={value} onValueChange={onChange} {...rest}>
      <SelectTrigger className={className} size={size}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => {
          const [v, l] = Array.isArray(o) ? o : [o, o];
          return <SelectItem key={v} value={v}>{l}</SelectItem>;
        })}
      </SelectContent>
    </Select>
  );
}

export function CopyField({ value }) {
  const [done, setDone] = useState(false);
  const copy = async () => {
    if (await copyText(value)) {
      setDone(true);
      setTimeout(() => setDone(false), 1500);
    } else toast('Copy failed, select the text manually', 'err');
  };
  return (
    <div className="flex gap-2">
      <Input readOnly value={value} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} />
      <Button type="button" variant="outline" onClick={copy}>
        {done ? <Check className="text-success" /> : <Copy />}
        {done ? 'Copied' : 'Copy'}
      </Button>
    </div>
  );
}

export function Alert({ variant, children, className }) {
  const Icon = variant === 'destructive' ? CircleAlert : Info;
  return (
    <div
      role="alert"
      className={cn(
        'flex items-start gap-2.5 rounded-md border px-3.5 py-2.5 text-[13px] [overflow-wrap:anywhere]',
        variant === 'destructive' ? 'border-destructive/40 bg-destructive/8 text-destructive' : 'border-info/30 bg-info/8',
        className,
      )}
    >
      <Icon className={cn('mt-0.5 size-4 shrink-0', variant !== 'destructive' && 'text-info')} />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}

export const Loading = ({ error }) =>
  error ? <Alert variant="destructive">{error}</Alert> : <div className="p-6 text-center text-sm text-muted-foreground">Loading...</div>;

export const Empty = ({ children, className }) => (
  <div className={cn('p-6 text-center text-[13px] text-muted-foreground', className)}>{children}</div>
);

export function PageHead({ title, subtitle, children, back }) {
  return (
    <header className="flex flex-wrap items-start justify-between gap-4">
      <div className="min-w-0">
        <h1 className="m-0 flex min-w-0 items-center gap-2.5 text-2xl font-semibold leading-tight">
          {back && (
            <Button asChild variant="ghost" size="icon-sm" className="-ml-2">
              <a href={back} aria-label="Back"><ArrowLeft /></a>
            </Button>
          )}
          {title}
        </h1>
        {subtitle && <p className="m-0 mt-1 text-[13px] text-muted-foreground">{subtitle}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}

export const SectionHeading = ({ children }) => (
  <h3 className="m-0 text-[11px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">{children}</h3>
);

/** Runs an async action with a busy flag; returns its result (or true), or undefined after toasting the error. */
export function useAction() {
  const [busy, setBusy] = useState(false);
  const run = async (fn, okMsg) => {
    setBusy(true);
    try {
      const r = await fn();
      if (okMsg) toast(okMsg);
      return r ?? true;
    } catch (e) {
      toast(e.message, 'err');
      return undefined;
    } finally {
      setBusy(false);
    }
  };
  return [busy, run];
}
