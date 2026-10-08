import { cn } from '@/lib/utils';

// shadcn Table with a dense data-table look. Add `cards` to turn rows
// into stacked cards below md (cells label themselves via data-label).
export const Table = ({ className, cards, ...props }) => (
  <div data-slot="table-container" className="relative w-full overflow-x-auto">
    <table data-slot="table" className={cn('w-full caption-bottom border-collapse text-[13px] tabular-nums', cards && 'table-cards', className)} {...props} />
  </div>
);
export const TableHeader = ({ className, ...props }) => <thead data-slot="table-header" className={cn('[&_tr]:border-b', className)} {...props} />;
export const TableBody = ({ className, ...props }) => <tbody data-slot="table-body" className={cn('[&_tr:last-child]:border-0', className)} {...props} />;
export const TableRow = ({ className, ...props }) => (
  <tr data-slot="table-row" className={cn('border-b transition-colors hover:bg-muted/60', className)} {...props} />
);
export const TableHead = ({ className, ...props }) => (
  <th
    data-slot="table-head"
    className={cn('h-9 whitespace-nowrap bg-muted px-3.5 text-left align-middle text-[11px] font-medium uppercase tracking-[0.06em] text-muted-foreground', className)}
    {...props}
  />
);
export const TableCell = ({ className, ...props }) => (
  <td data-slot="table-cell" className={cn('px-3.5 py-2.5 align-middle', className)} {...props} />
);
