import { useState, useEffect, useRef } from 'react';
import * as d3 from 'd3';

const STATUS_COLORS = {
  ALLOWED: '#06d6a0',
  DENIED: '#5a5e72',
  VULNERABLE: '#ff4d6d',
  UNKNOWN: '#333645',
};

const STATUS_ICONS = {
  ALLOWED: '✅',
  DENIED: '🚫',
  VULNERABLE: '🔴',
  UNKNOWN: '❓',
};

export default function MatrixPage() {
  const svgRef = useRef(null);
  const [matrixData, setMatrixData] = useState(null);
  const [tooltip, setTooltip] = useState(null);
  const [scanId, setScanId] = useState(() => localStorage.getItem('bac_last_scan_id') || '');
  const [error, setError] = useState('');

  const loadGraph = async (idToLoad = scanId) => {
    if (!idToLoad.trim()) return setError('Enter a Scan ID');
    setError('');
    try {
      const { scansAPI } = await import('../services/api');
      const res = await scansAPI.graph(scanId.trim());
      setMatrixData(res.data);
    } catch (e) {
      setError('Could not load graph data for this scan ID');
    }
  };

  useEffect(() => {
    if (!matrixData || !svgRef.current) return;
    renderMatrix(matrixData, svgRef.current, setTooltip);
  }, [matrixData]);

  // Auto-load if we have a scan ID from localStorage
  useEffect(() => {
    if (scanId) {
      loadGraph(scanId);
    }
  }, []);

  return (
    <div className="fade-in">
      <div className="page-header">
        <div>
          <div className="page-title">🗺️ Access Matrix</div>
          <div className="page-subtitle">Visual heatmap of endpoint × role access permissions</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label className="form-label">Scan ID</label>
            <input className="input" placeholder="Enter scan ID from scanner..."
              value={scanId} onChange={e => setScanId(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && loadGraph()} />
          </div>
          <button className="btn btn-primary" onClick={loadGraph}>Load Matrix</button>
        </div>
        {error && <div className="alert error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 20, marginBottom: 20, flexWrap: 'wrap' }}>
        {Object.entries(STATUS_COLORS).map(([status, color]) => (
          <div key={status} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
            <div style={{ width: 14, height: 14, borderRadius: 3, background: color }} />
            {STATUS_ICONS[status]} {status}
          </div>
        ))}
      </div>

      <div className="card" style={{ overflowX: 'auto', position: 'relative' }}>
        {!matrixData ? (
          <div className="empty-state">
            <div className="empty-state-icon">🗺️</div>
            <div className="empty-state-title">No matrix loaded</div>
            <div className="empty-state-desc">Enter a Scan ID above to visualize the access control matrix.</div>
          </div>
        ) : (
          <svg ref={svgRef} style={{ display: 'block', minWidth: '100%' }} />
        )}

        {tooltip && (
          <div style={{
            position: 'fixed', top: tooltip.y + 10, left: tooltip.x + 10,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '10px 14px', zIndex: 1000,
            fontSize: 12, boxShadow: 'var(--shadow)', minWidth: 200, pointerEvents: 'none'
          }}>
            <div style={{ fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>
              {STATUS_ICONS[tooltip.status]} {tooltip.status}
            </div>
            <div style={{ color: 'var(--text-secondary)', marginBottom: 3 }}>
              <strong>Endpoint:</strong> <code style={{ fontFamily: 'JetBrains Mono', fontSize: 11 }}>{tooltip.endpoint}</code>
            </div>
            <div style={{ color: 'var(--text-secondary)', marginBottom: 3 }}>
              <strong>Persona:</strong> {tooltip.persona}
            </div>
            {tooltip.vuln_type && (
              <div style={{ color: 'var(--critical)', marginTop: 6 }}>
                ⚠️ Vulnerability: <strong>{tooltip.vuln_type?.replace(/_/g, ' ')}</strong>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}


function renderMatrix(data, svgEl, setTooltip) {
  const { endpoints, personas, cells } = data;
  if (!endpoints.length || !personas.length) return;

  const cellSize = 44;
  const labelWidth = Math.min(320, Math.max(200, endpoints.reduce((a, e) => Math.max(a, e.length * 7), 0)));
  const personaHeight = 60;
  const width = labelWidth + personas.length * cellSize + 20;
  const height = personaHeight + endpoints.length * cellSize + 20;

  const svg = d3.select(svgEl)
    .attr('width', width)
    .attr('height', height);
  svg.selectAll('*').remove();

  // Persona headers
  personas.forEach((persona, pi) => {
    svg.append('text')
      .attr('x', labelWidth + pi * cellSize + cellSize / 2)
      .attr('y', personaHeight - 10)
      .attr('text-anchor', 'middle')
      .attr('fill', '#8b8fa8')
      .attr('font-size', 11)
      .attr('font-family', 'Inter, sans-serif')
      .attr('font-weight', 600)
      .text(persona.length > 10 ? persona.slice(0, 9) + '…' : persona);
  });

  // Endpoint labels
  endpoints.forEach((endpoint, ei) => {
    svg.append('text')
      .attr('x', labelWidth - 8)
      .attr('y', personaHeight + ei * cellSize + cellSize / 2 + 4)
      .attr('text-anchor', 'end')
      .attr('fill', '#8b8fa8')
      .attr('font-size', 11)
      .attr('font-family', 'JetBrains Mono, monospace')
      .text(endpoint.length > 36 ? '...' + endpoint.slice(-34) : endpoint);
  });

  // Cells
  cells.forEach(cell => {
    const ei = endpoints.indexOf(cell.endpoint);
    const pi = personas.indexOf(cell.persona);
    if (ei < 0 || pi < 0) return;

    const x = labelWidth + pi * cellSize + 2;
    const y = personaHeight + ei * cellSize + 2;
    const s = cellSize - 4;

    const rect = svg.append('rect')
      .attr('x', x).attr('y', y)
      .attr('width', s).attr('height', s)
      .attr('rx', 4)
      .attr('fill', STATUS_COLORS[cell.status] || STATUS_COLORS.UNKNOWN)
      .attr('opacity', 0.8)
      .attr('cursor', 'pointer')
      .on('mouseover', (event) => {
        setTooltip({ ...cell, x: event.clientX, y: event.clientY });
        d3.select(event.currentTarget).attr('opacity', 1).attr('stroke', '#fff').attr('stroke-width', 1.5);
      })
      .on('mousemove', (event) => {
        setTooltip(t => t ? { ...t, x: event.clientX, y: event.clientY } : null);
      })
      .on('mouseout', (event) => {
        setTooltip(null);
        d3.select(event.currentTarget).attr('opacity', 0.8).attr('stroke', 'none');
      });

    // Icon inside cell
    svg.append('text')
      .attr('x', x + s / 2).attr('y', y + s / 2 + 5)
      .attr('text-anchor', 'middle')
      .attr('font-size', 14)
      .attr('pointer-events', 'none')
      .text(STATUS_ICONS[cell.status] || '❓');
  });
}
