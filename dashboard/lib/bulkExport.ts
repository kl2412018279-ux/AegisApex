// lib/bulkExport.ts
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import { supabase } from '@/lib/supabase';

export interface Device {
  id: string;
  hostname?: string;
  ip_address?: string;
  management_ip?: string;
  vendor?: string;
  netmiko_type?: string;
  suppliers?: { name?: string } | null;
  risk_level?: string | null;
}

export async function exportBulkPDF(
  devices: Device[],
  riskFilter: string = 'ALL'
): Promise<void> {
  if (typeof window === 'undefined') return;

  if (!devices || devices.length === 0) {
    throw new Error(`No devices available under the "${riskFilter}" threat filter.`);
  }

  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
  });

  const timestamp = new Date().toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });

  const normalizedFilter = riskFilter.toUpperCase();

  // Dynamic Header Title based on Threat Level
  const reportTitle =
    normalizedFilter === 'ALL'
      ? 'AIOps SecureWatch - Complete Inventory Audit'
      : `AIOps SecureWatch - ${normalizedFilter} Threat Level Report`;

  // --- Header Banner ---
  if (['CRITICAL', 'HIGH'].includes(normalizedFilter)) {
    doc.setFillColor(153, 27, 27); // Dark Red
  } else {
    doc.setFillColor(15, 23, 42); // Slate 900
  }
  
  doc.rect(0, 0, 210, 28, 'F');

  doc.setTextColor(255, 255, 255);
  doc.setFontSize(13);
  doc.setFont('helvetica', 'bold');
  doc.text(reportTitle, 14, 12);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(226, 232, 240);
  doc.text(
    `Generated: ${timestamp}  |  Filtered Risk: ${normalizedFilter}  |  Matching Assets: ${devices.length}`,
    14,
    20
  );

  // --- Fetch Scan Summaries Safely ---
  const deviceIds = devices.map((d) => d.id);
  const scanMap: Record<string, { risk_level: string; summary: string }> = {};

  try {
    const { data: scansData, error } = await supabase
      .from('scans')
      .select('device_id, risk_level, summary, created_at')
      .in('device_id', deviceIds)
      .order('created_at', { ascending: false });

    if (!error && scansData) {
      for (const scan of scansData) {
        if (scan.device_id && !scanMap[scan.device_id]) {
          scanMap[scan.device_id] = {
            risk_level: scan.risk_level || 'UNASSESSED',
            summary: scan.summary || 'No detailed analysis summary available.',
          };
        }
      }
    }
  } catch (err) {
    console.warn('Unable to fetch extended scan telemetry for PDF export:', err);
  }

  // --- Device Table Matrix ---
  const tableRows = devices.map((device, index) => {
    const scan = scanMap[device.id] || {};
    const riskLevel = scan.risk_level || device.risk_level || 'UNASSESSED';
    const supplierName = device.suppliers?.name || 'Internal';
    const ip = device.ip_address || device.management_ip || '0.0.0.0';

    return [
      (index + 1).toString(),
      String(device.hostname || 'Unknown Host'),
      String(ip),
      `${device.vendor || 'Cisco'} (${device.netmiko_type || 'ios'})`,
      String(supplierName),
      String(riskLevel).toUpperCase(),
    ];
  });

  autoTable(doc, {
    startY: 34,
    head: [['#', 'Hostname', 'IP Address', 'Vendor / Type', 'Supplier', 'Threat Level']],
    body: tableRows,
    theme: 'grid',
    headStyles: {
      fillColor: [30, 41, 59],
      textColor: [255, 255, 255],
      fontSize: 8,
      fontStyle: 'bold',
    },
    bodyStyles: {
      fontSize: 8,
      textColor: [51, 65, 85],
    },
    columnStyles: {
      0: { cellWidth: 10 },
      1: { cellWidth: 40 },
      2: { cellWidth: 35 },
      3: { cellWidth: 45 },
      4: { cellWidth: 35 },
      5: { cellWidth: 25, fontStyle: 'bold' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 5) {
        const val = String(data.cell.raw).toUpperCase();
        if (val.includes('CRITICAL') || val.includes('HIGH')) {
          data.cell.styles.textColor = [225, 29, 72];
        } else if (val.includes('MED') || val.includes('WARNING')) {
          data.cell.styles.textColor = [217, 119, 6];
        } else if (val.includes('LOW') || val.includes('SAFE')) {
          data.cell.styles.textColor = [16, 185, 129];
        }
      }
    },
  });

  // --- Detailed Telemetry Breakdown Section ---
  let finalY = (doc as any).lastAutoTable.finalY + 10;

  if (finalY > 250) {
    doc.addPage();
    finalY = 20;
  }

  doc.setFontSize(10);
  doc.setFont('helvetica', 'bold');
  doc.setTextColor(15, 23, 42);
  doc.text(`Security Telemetry Breakdown (${normalizedFilter})`, 14, finalY);

  finalY += 6;

  devices.forEach((device) => {
    const cardHeight = 22;
    if (finalY + cardHeight > 275) {
      doc.addPage();
      finalY = 20;
    }

    const scan = scanMap[device.id];
    const summaryText = scan?.summary || 'No vulnerability assessment log found.';
    const ip = device.ip_address || device.management_ip || '0.0.0.0';

    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.roundedRect(14, finalY, 182, cardHeight, 1, 1, 'FD');

    doc.setFontSize(8);
    doc.setFont('helvetica', 'bold');
    doc.setTextColor(15, 23, 42);
    doc.text(`${device.hostname || 'Unknown Host'} (${ip})`, 18, finalY + 6);

    doc.setFont('helvetica', 'normal');
    doc.setTextColor(71, 85, 105);

    const splitSummary = doc.splitTextToSize(summaryText.replace(/\n/g, ' '), 174);
    const summaryLine = splitSummary[0]
      ? splitSummary[0].length > 110
        ? splitSummary[0].slice(0, 110) + '...'
        : splitSummary[0]
      : 'No details available.';

    doc.text(summaryLine, 18, finalY + 14);

    finalY += cardHeight + 4;
  });

  // --- Automated Page Number Footers ---
  const pageCount = (doc as any).internal.getNumberOfPages();
  for (let i = 1; i <= pageCount; i++) {
    doc.setPage(i);
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(148, 163, 184);
    doc.text(
      `Page ${i} of ${pageCount} — Confidential • SecOps Center Audit`,
      105,
      290,
      { align: 'center' }
    );
  }

  const fileName = `${normalizedFilter.toLowerCase()}_threat_audit_${new Date().toISOString().slice(0, 10)}.pdf`;
  doc.save(fileName);
}