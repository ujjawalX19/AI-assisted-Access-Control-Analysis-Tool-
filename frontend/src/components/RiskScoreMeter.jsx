import { useEffect, useRef } from 'react';

const SEVERITY_COLORS = {
  CRITICAL: '#ff4d6d',
  HIGH: '#ff8c42',
  MEDIUM: '#ffd166',
  LOW: '#06d6a0',
};

const SEVERITY_GLOW = {
  CRITICAL: 'rgba(255,77,109,0.4)',
  HIGH: 'rgba(255,140,66,0.4)',
  MEDIUM: 'rgba(255,209,102,0.4)',
  LOW: 'rgba(6,214,160,0.4)',
};

export default function RiskScoreMeter({ score = 0, severity = 'LOW', size = 80, animate = true }) {
  const canvasRef = useRef(null);
  const animRef = useRef(null);
  const currentRef = useRef(0);

  const color = SEVERITY_COLORS[severity] || '#7c6df8';
  const glowColor = SEVERITY_GLOW[severity] || 'rgba(124,109,248,0.4)';

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    ctx.scale(dpr, dpr);

    const cx = size / 2;
    const cy = size / 2;
    const r = size / 2 - 6;
    const startAngle = Math.PI * 0.75;
    const totalAngle = Math.PI * 1.5;

    const draw = (val) => {
      ctx.clearRect(0, 0, size, size);

      // Background track
      ctx.beginPath();
      ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle);
      ctx.strokeStyle = 'rgba(255,255,255,0.08)';
      ctx.lineWidth = 6;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Progress arc
      const pct = Math.min(val / 100, 1);
      if (pct > 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, r, startAngle, startAngle + totalAngle * pct);
        ctx.strokeStyle = color;
        ctx.lineWidth = 6;
        ctx.lineCap = 'round';
        ctx.shadowColor = glowColor;
        ctx.shadowBlur = 10;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }

      // Score text
      ctx.fillStyle = color;
      ctx.font = `bold ${size < 70 ? 14 : 18}px Inter, sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(Math.round(val), cx, cy - 4);

      // /100 label
      ctx.fillStyle = 'rgba(255,255,255,0.35)';
      ctx.font = `${size < 70 ? 8 : 10}px Inter, sans-serif`;
      ctx.fillText('/100', cx, cy + (size < 70 ? 10 : 13));
    };

    if (animate) {
      const target = score;
      const duration = 900;
      const start = performance.now();
      const from = currentRef.current;

      const step = (now) => {
        const t = Math.min((now - start) / duration, 1);
        const ease = 1 - Math.pow(1 - t, 3);
        const val = from + (target - from) * ease;
        currentRef.current = val;
        draw(val);
        if (t < 1) animRef.current = requestAnimationFrame(step);
      };
      animRef.current = requestAnimationFrame(step);
    } else {
      draw(score);
    }

    return () => cancelAnimationFrame(animRef.current);
  }, [score, severity, size, animate]);

  return <canvas ref={canvasRef} style={{ display: 'block' }} />;
}
