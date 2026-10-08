import { cn } from '@/lib/utils';

export const Card = ({ className, ...props }) => (
  <div data-slot="card" className={cn('flex min-w-0 flex-col gap-4 rounded-lg border bg-card p-4 text-card-foreground shadow-sm sm:p-6', className)} {...props} />
);
export const CardHeader = ({ className, ...props }) => (
  <div data-slot="card-header" className={cn('flex flex-wrap items-center gap-x-3 gap-y-2', className)} {...props} />
);
export const CardTitle = ({ className, ...props }) => (
  <h2 data-slot="card-title" className={cn('m-0 flex flex-wrap items-center gap-2 text-base font-semibold leading-tight', className)} {...props} />
);
export const CardDescription = ({ className, ...props }) => (
  <p data-slot="card-description" className={cn('m-0 text-[13px] text-muted-foreground', className)} {...props} />
);
export const CardAction = ({ className, ...props }) => (
  <div data-slot="card-action" className={cn('ml-auto flex flex-wrap items-center gap-2', className)} {...props} />
);
export const CardContent = ({ className, ...props }) => <div data-slot="card-content" className={cn('min-w-0', className)} {...props} />;
export const CardFooter = ({ className, ...props }) => (
  <div data-slot="card-footer" className={cn('flex flex-wrap items-center gap-2', className)} {...props} />
);
