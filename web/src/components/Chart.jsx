import { useEffect, useRef, useState } from 'preact/hooks';
import uPlot from 'uplot';
import 'uplot/dist/uPlot.min.css';
import { getTheme, onTheme } from '../theme.js';

const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

/**
 * uPlot time-series chart that tracks its container width and the theme.
 * @param {{data: any[][], series: {label: string, color: string, fill?: boolean}[], fmt: (v: number) => string, height?: number}} props
 * series[].color is a CSS custom property name, e.g. "--success".
 */
export function Chart({ data, series, fmt, height = 220 }) {
  const box = useRef(null);
  const plot = useRef(null);
  const [theme, setTheme] = useState(getTheme);

  useEffect(() => onTheme(setTheme), []);

  useEffect(() => {
    const el = box.current;
    const axis = {
      stroke: css('--muted-foreground'),
      grid: { stroke: css('--border'), width: 1, dash: [2, 3] },
      ticks: { stroke: css('--border'), width: 1, size: 4 },
      font: '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
    };
    const opts = {
      width: el.clientWidth,
      height,
      cursor: { drag: { x: false, y: false }, points: { size: 6 } },
      scales: { y: { range: (u, min, max) => [0, max > 0 ? max * 1.1 : 1] } },
      series: [
        {},
        ...series.map((s) => {
          const c = css(s.color);
          return {
            label: s.label,
            stroke: c,
            width: 2,
            fill: s.fill ? c + '1f' : undefined,
            points: { show: false },
            value: (u, v) => (v == null ? '-' : fmt(v)),
          };
        }),
      ],
      axes: [axis, { ...axis, size: 64, values: (u, vals) => vals.map(fmt) }],
    };
    plot.current = new uPlot(opts, data, el);
    const ro = new ResizeObserver(() => plot.current.setSize({ width: el.clientWidth, height }));
    ro.observe(el);
    return () => {
      ro.disconnect();
      plot.current.destroy();
      plot.current = null;
    };
  }, [theme, height, series.length]);

  useEffect(() => {
    plot.current?.setData(data);
  }, [data]);

  return <div className="chart w-full min-w-0 overflow-hidden" ref={box} />;
}

export const trafficSeries = [
  { label: 'Down', color: '--success', fill: true },
  { label: 'Up', color: '--warning', fill: true },
];
