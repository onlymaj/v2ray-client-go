import { forwardRef } from 'react';
import * as LabelPrimitive from '@radix-ui/react-label';
import { cn } from '@/lib/utils';

export const Label = forwardRef(function Label({ className, ...props }, ref) {
  return (
    <LabelPrimitive.Root
      ref={ref}
      data-slot="label"
      className={cn('flex select-none items-center gap-2 text-xs font-medium text-muted-foreground peer-disabled:opacity-50', className)}
      {...props}
    />
  );
});
