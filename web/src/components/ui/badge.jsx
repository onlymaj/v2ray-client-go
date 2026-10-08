import { cva } from 'class-variance-authority';
import { cn } from '@/lib/utils';

// Pill badges: uppercase, tinted background.
export const badgeVariants = cva(
  'inline-flex w-fit shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium uppercase tracking-[0.04em] [&>svg]:size-3',
  {
    variants: {
      variant: {
        default: 'bg-secondary text-muted-foreground',
        success: 'bg-success/12 text-success',
        warning: 'bg-warning/14 text-warning',
        destructive: 'bg-destructive/14 text-destructive',
        info: 'bg-info/14 text-info',
        outline: 'border border-border text-muted-foreground',
      },
    },
    defaultVariants: { variant: 'default' },
  },
);

export const Badge = ({ className, variant, ...props }) => (
  <span data-slot="badge" className={cn(badgeVariants({ variant }), className)} {...props} />
);
