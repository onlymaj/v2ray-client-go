import { forwardRef } from 'react';
import { cn } from '@/lib/utils';

export const inputClass =
  'flex h-9 w-full min-w-0 rounded-md border border-input bg-background px-3 py-1 text-sm shadow-xs transition-[color,box-shadow] outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/30 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive';

export const Input = forwardRef(function Input({ className, type, ...props }, ref) {
  return <input ref={ref} type={type} data-slot="input" className={cn(inputClass, className)} {...props} />;
});
