import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';

const SEVERITY_RGB = {
  CRITICAL: [220, 38, 38],
  HIGH: [234, 88, 12],
  MEDIUM: [202, 138, 4],
  LOW: [22, 163, 74],
  INFO: [37, 99, 235],
};

function hexToRgb(hex) {
  const r = parseInt(hex.slice(1, 3), 16);
  const g = parseInt(hex.slice(3, 5), 16);
  const b = parseInt(hex.slice(5, 7), 16);
  return [r, g, b];
}

function drawCoverPage(doc, projectName, scanDate, findings) {
  const w = doc.internal.pageSize.getWidth();
  const h = doc.internal.pageSize.getHeight();

  // Dark background
  doc.setFillColor(10, 11, 15);
  doc.rect(0, 0, w, h, 'F');

  // Top accent bar
  doc.setFillColor(124, 109, 248);
  doc.rect(0, 0, w, 3, 'F');

  // Gradient-like side panel
  doc.setFillColor(22, 24, 32);
  doc.rect(0, 3, 60, h - 3, 'F');

  // Left vertical accent line
  doc.setFillColor(124, 109, 248);
  doc.rect(60, 3, 1, h - 3, 'F');

  // Logo area (left)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9);
  doc.setTextColor(124, 109, 248);
  doc.text('BAC', 30, 40, { align: 'center' });
  doc.setFontSize(7);
  doc.setTextColor(90, 94, 114);
  doc.text('SCANNER', 30, 47, { align: 'center' });

  // Decorative dots  
  const dots = [[30, 70], [30, 80], [30, 90]];
  dots.forEach(([x, y]) => {
    doc.setFillColor(42, 45, 58);
    doc.circle(x, y, 2, 'F');
  });

  // Shield icon area
  doc.setFillColor(30, 32, 45);
  doc.roundedRect(75, 25, 120, 80, 4, 4, 'F');
  doc.setFillColor(124, 109, 248);
  doc.roundedRect(75, 25, 120, 3, 1, 1, 'F');

  // Main title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(232, 234, 240);
  doc.text('AI-ENHANCED', 135, 52, { align: 'center' });
  doc.setFontSize(14);
  doc.setTextColor(124, 109, 248);
  doc.text('SECURITY ASSESSMENT REPORT', 135, 64, { align: 'center' });

  doc.setFontSize(9);
  doc.setTextColor(90, 94, 114);
  doc.text('Broken Access Control Analysis', 135, 75, { align: 'center' });

  // Horizontal divider
  doc.setDrawColor(42, 45, 58);
  doc.line(75, 82, 195, 82);

  doc.setFontSize(8);
  doc.setTextColor(139, 143, 168);
  doc.text('Powered by AI Risk Scoring Engine  ·  OWASP A01:2021', 135, 91, { align: 'center' });

  // Info grid
  const infoY = 120;
  const infos = [
    { label: 'PROJECT', value: projectName || 'Unnamed Project' },
    { label: 'REPORT DATE', value: scanDate },
    { label: 'TOOL VERSION', value: 'BAC Scanner v1.0' },
    { label: 'FRAMEWORK', value: 'OWASP Top 10 · CWE · CVSS' },
  ];

  infos.forEach((info, i) => {
    const x = i % 2 === 0 ? 75 : 140;
    const y = infoY + Math.floor(i / 2) * 28;
    doc.setFillColor(22, 24, 32);
    doc.roundedRect(x, y, 58, 20, 2, 2, 'F');
    doc.setFontSize(7);
    doc.setTextColor(90, 94, 114);
    doc.text(info.label, x + 4, y + 7);
    doc.setFontSize(8);
    doc.setTextColor(232, 234, 240);
    doc.text(String(info.value).substring(0, 22), x + 4, y + 15);
  });

  // Severity summary boxes
  const sevY = 185;
  doc.setFontSize(8);
  doc.setTextColor(90, 94, 114);
  doc.text('VULNERABILITY SUMMARY', 75, sevY);

  const counts = {
    CRITICAL: findings.filter(f => f.severity === 'CRITICAL' || f.ai_severity === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity === 'HIGH' || f.ai_severity === 'HIGH').length,
    MEDIUM: findings.filter(f => f.severity === 'MEDIUM' || f.ai_severity === 'MEDIUM').length,
    LOW: findings.filter(f => f.severity === 'LOW' || f.ai_severity === 'LOW').length,
  };

  const sevBoxes = [
    { sev: 'CRITICAL', color: [220, 38, 38], x: 75 },
    { sev: 'HIGH', color: [234, 88, 12], x: 107 },
    { sev: 'MEDIUM', color: [202, 138, 4], x: 139 },
    { sev: 'LOW', color: [22, 163, 74], x: 171 },
  ];

  sevBoxes.forEach(({ sev, color, x }) => {
    doc.setFillColor(22, 24, 32);
    doc.roundedRect(x, sevY + 5, 28, 30, 2, 2, 'F');
    doc.setFillColor(...color);
    doc.roundedRect(x, sevY + 5, 28, 3, 1, 1, 'F');
    doc.setFontSize(16);
    doc.setTextColor(...color);
    doc.text(String(counts[sev] || 0), x + 14, sevY + 23, { align: 'center' });
    doc.setFontSize(6);
    doc.setTextColor(90, 94, 114);
    doc.text(sev, x + 14, sevY + 31, { align: 'center' });
  });

  // Footer
  doc.setFontSize(7);
  doc.setTextColor(42, 45, 58);
  doc.text('CONFIDENTIAL — AI-Assisted Access Control Analysis Tool', w / 2, h - 8, { align: 'center' });
  doc.setTextColor(90, 94, 114);
  doc.text('We enhanced this report using AI to prioritize vulnerabilities based on risk.', w / 2, h - 3, { align: 'center' });
}

export function generatePDFReport({ findings = [], projectName = '', scanDate = '' }) {
  const doc = new jsPDF({ orientation: 'portrait', unit: 'mm', format: 'a4' });

  const date = scanDate || new Date().toLocaleDateString('en-US', {
    year: 'numeric', month: 'long', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });

  // === COVER PAGE ===
  drawCoverPage(doc, projectName, date, findings);

  if (findings.length === 0) {
    doc.save(`BAC-Report-${projectName || 'scan'}.pdf`);
    return;
  }

  // === FINDINGS TABLE PAGE ===
  doc.addPage();

  // Dark bg
  doc.setFillColor(10, 11, 15);
  doc.rect(0, 0, 210, 297, 'F');
  doc.setFillColor(124, 109, 248);
  doc.rect(0, 0, 210, 3, 'F');

  // Page title
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(232, 234, 240);
  doc.text('FINDINGS OVERVIEW', 15, 18);

  doc.setFontSize(8);
  doc.setTextColor(90, 94, 114);
  doc.text(`${findings.length} vulnerabilities detected  ·  AI Risk Scoring Applied`, 15, 25);

  // AI notice banner
  doc.setFillColor(22, 24, 32);
  doc.roundedRect(15, 28, 180, 12, 2, 2, 'F');
  doc.setFillColor(124, 109, 248);
  doc.roundedRect(15, 28, 3, 12, 1, 1, 'F');
  doc.setFontSize(7);
  doc.setTextColor(139, 143, 168);
  doc.text('🤖  AI INSIGHT: We enhanced this tool using AI to prioritize vulnerabilities based on risk.', 22, 36);

  // Findings table
  const tableRows = findings.map((f, i) => [
    i + 1,
    f.vuln_type?.replace(/_/g, ' ') || '—',
    f.endpoint || '—',
    f.method || '—',
    f.severity || '—',
    `${f.ai_risk_score ?? '—'}/100`,
    f.ai_severity || '—',
    f.ai_confidence || '—',
    f.cwe_id || '—',
  ]);

  autoTable(doc, {
    startY: 44,
    head: [['#', 'Vulnerability', 'Endpoint', 'Method', 'Severity', 'AI Score', 'AI Sev.', 'Confidence', 'CWE']],
    body: tableRows,
    styles: {
      fillColor: [22, 24, 32],
      textColor: [139, 143, 168],
      fontSize: 7,
      cellPadding: 3,
      lineColor: [42, 45, 58],
      lineWidth: 0.1,
    },
    headStyles: {
      fillColor: [16, 18, 24],
      textColor: [90, 94, 114],
      fontSize: 6.5,
      fontStyle: 'bold',
    },
    alternateRowStyles: {
      fillColor: [18, 20, 28],
    },
    didParseCell: (data) => {
      if (data.section === 'body') {
        const row = findings[data.row.index];
        if (!row) return;
        // Color severity column
        if (data.column.index === 4) {
          const rgb = SEVERITY_RGB[row.severity] || [139, 143, 168];
          data.cell.styles.textColor = rgb;
          data.cell.styles.fontStyle = 'bold';
        }
        // Color AI severity column
        if (data.column.index === 6) {
          const rgb = SEVERITY_RGB[row.ai_severity] || [124, 109, 248];
          data.cell.styles.textColor = rgb;
          data.cell.styles.fontStyle = 'bold';
        }
        // Color AI score
        if (data.column.index === 5) {
          const score = row.ai_risk_score || 0;
          if (score >= 85) data.cell.styles.textColor = [220, 38, 38];
          else if (score >= 68) data.cell.styles.textColor = [234, 88, 12];
          else if (score >= 45) data.cell.styles.textColor = [202, 138, 4];
          else data.cell.styles.textColor = [22, 163, 74];
        }
      }
    },
    margin: { left: 15, right: 15 },
  });

  // === DETAILED FINDINGS PAGES ===
  findings.forEach((f, idx) => {
    doc.addPage();

    doc.setFillColor(10, 11, 15);
    doc.rect(0, 0, 210, 297, 'F');
    const sevColor = SEVERITY_RGB[f.severity] || [124, 109, 248];
    doc.setFillColor(...sevColor);
    doc.rect(0, 0, 210, 3, 'F');

    // Finding header
    doc.setFillColor(22, 24, 32);
    doc.rect(0, 3, 210, 28, 'F');

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6);
    doc.setTextColor(...sevColor);
    doc.text(`FINDING ${idx + 1} OF ${findings.length}  ·  ${f.severity}`, 15, 12);

    doc.setFontSize(12);
    doc.setTextColor(232, 234, 240);
    doc.text(f.vuln_type?.replace(/_/g, ' ') || 'Unknown', 15, 22);

    doc.setFontSize(8);
    doc.setTextColor(90, 94, 114);
    doc.text(`${f.method || 'GET'}  ${f.endpoint || '/'}`, 15, 29);

    // AI Score badge (top right)
    const aiScore = f.ai_risk_score ?? 0;
    const aiColor = SEVERITY_RGB[f.ai_severity] || [124, 109, 248];
    doc.setFillColor(16, 18, 24);
    doc.roundedRect(160, 6, 35, 20, 2, 2, 'F');
    doc.setFillColor(...aiColor);
    doc.roundedRect(160, 6, 35, 2, 1, 1, 'F');
    doc.setFontSize(6);
    doc.setTextColor(90, 94, 114);
    doc.text('AI RISK SCORE', 177.5, 13, { align: 'center' });
    doc.setFontSize(13);
    doc.setTextColor(...aiColor);
    doc.setFont('helvetica', 'bold');
    doc.text(`${aiScore}/100`, 177.5, 22, { align: 'center' });

    let y = 42;

    // AI Reasoning
    doc.setFillColor(16, 18, 28);
    doc.roundedRect(15, y, 180, 24, 2, 2, 'F');
    doc.setFillColor(124, 109, 248);
    doc.roundedRect(15, y, 2, 24, 1, 1, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7);
    doc.setTextColor(124, 109, 248);
    doc.text('AI ANALYSIS', 21, y + 7);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(139, 143, 168);
    const reasonLines = doc.splitTextToSize(f.ai_reasoning || 'No AI analysis available.', 168);
    doc.text(reasonLines.slice(0, 2), 21, y + 14);
    y += 30;

    // Explanation
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(232, 234, 240);
    doc.text('EXPLANATION', 15, y);
    y += 5;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(139, 143, 168);
    const explLines = doc.splitTextToSize(f.explanation || 'No explanation.', 180);
    doc.text(explLines.slice(0, 8), 15, y);
    y += Math.min(explLines.length, 8) * 4 + 8;

    // Fix suggestion
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(7.5);
    doc.setTextColor(232, 234, 240);
    doc.text('REMEDIATION', 15, y);
    y += 5;
    doc.setFillColor(14, 16, 20);
    const fixText = f.fix_suggestion || 'See OWASP guidelines.';
    const fixLines = doc.splitTextToSize(fixText, 176);
    const fixH = Math.min(fixLines.length, 10) * 4 + 8;
    doc.roundedRect(15, y, 180, fixH, 2, 2, 'F');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(6, 214, 160);
    doc.text(fixLines.slice(0, 10), 19, y + 5);
    y += fixH + 8;

    // References
    if (f.cwe_id || f.owasp_ref) {
      doc.setFillColor(22, 24, 32);
      doc.roundedRect(15, y, 180, 14, 2, 2, 'F');
      doc.setFontSize(7);
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(90, 94, 114);
      doc.text('REFERENCES', 19, y + 6);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(76, 201, 240);
      doc.text(`${f.cwe_id || ''}  ${f.owasp_ref || ''}`, 19, y + 12);
    }

    // Page footer
    doc.setFontSize(6.5);
    doc.setTextColor(42, 45, 58);
    doc.text(`Page ${idx + 3} of ${findings.length + 2}  ·  BAC Scanner AI Security Report  ·  CONFIDENTIAL`, 105, 290, { align: 'center' });
  });

  doc.save(`BAC-Security-Report-${(projectName || 'scan').replace(/\s+/g, '-')}.pdf`);
}

export default function PDFExportButton({ findings, projectName }) {
  const handleExport = () => {
    generatePDFReport({
      findings,
      projectName,
      scanDate: new Date().toLocaleString(),
    });
  };

  return (
    <button
      className="btn btn-pdf"
      onClick={handleExport}
      title="Export full security report as PDF"
      id="export-pdf-btn"
    >
      <span>📄</span>
      Export PDF Report
    </button>
  );
}
