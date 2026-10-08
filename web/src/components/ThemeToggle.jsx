import { useEffect, useState } from 'preact/hooks';
import { Moon, Sun } from 'lucide-react';
import { getTheme, onTheme, setTheme } from '../theme.js';
import { Button } from './ui/button';

export function ThemeToggle() {
  const [t, setT] = useState(getTheme);
  useEffect(() => onTheme(setT), []);
  const next = t === 'dark' ? 'light' : 'dark';
  return (
    <Button variant="ghost" size="icon-sm" aria-label={`Switch to ${next} theme`} title={`Switch to ${next} theme`} onClick={() => setTheme(next)}>
      {t === 'dark' ? <Moon /> : <Sun />}
    </Button>
  );
}
