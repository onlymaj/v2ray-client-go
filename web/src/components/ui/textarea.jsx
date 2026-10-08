import { forwardRef } from 'react';
import { cn } from '@/lib/utils';
import { inputClass } from './input';

export const Textarea = forwardRef(function Textarea({ className, ...props }, ref) {
  return <textarea ref={ref} data-slot="textarea" className={cn(inputClass, 'h-auto min-h-16 py-2', className)} {...props} />;
});
