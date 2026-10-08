import { useState } from 'preact/hooks';
import { api } from '../api.js';
import { ThemeToggle } from '../components/ThemeToggle.jsx';
import { Alert, Field } from '../components/common.jsx';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';

export function Login({ onLogin }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await api('/login', { method: 'POST', body: { password } });
      onLogin();
    } catch (err) {
      setError(err.status === 401 ? 'Wrong password' : err.message);
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center p-4">
      <div className="absolute right-4 top-4"><ThemeToggle /></div>
      <Card className="w-full max-w-sm gap-5 p-6 sm:p-8">
        <form onSubmit={submit} className="flex flex-col gap-5">
          <div className="flex flex-col items-center gap-3 text-center">
            <span className="grid size-12 place-items-center rounded-full border bg-primary text-xl font-bold text-primary-foreground shadow-sm">V</span>
            <div>
              <h1 className="m-0 text-xl font-semibold">v2ray-client-go</h1>
              <p className="m-0 mt-1 text-[13px] text-muted-foreground">Sign in to manage proxy clients and routing.</p>
            </div>
          </div>
          <Field label="Password">
            <Input type="password" autoFocus autoComplete="current-password" value={password} onInput={(e) => setPassword(e.currentTarget.value)} required />
          </Field>
          {error && <Alert variant="destructive">{error}</Alert>}
          <Button type="submit" className="w-full" disabled={busy || !password}>{busy ? 'Signing in...' : 'Sign in'}</Button>
        </form>
      </Card>
    </div>
  );
}
