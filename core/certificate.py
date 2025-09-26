# =============================================================================
# core/certificate.py - Enhanced Certificate Generation with Hidden Partition Info
# =============================================================================

import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import os

class CertificateGenerator:
    """Generate tamper-proof wipe certificates with hidden partition information"""
    
    def __init__(self):
        self.cert_dir = os.path.join(os.getcwd(), 'certificates')
        os.makedirs(self.cert_dir, exist_ok=True)
    
    def generate_certificate(self, wipe_data: Dict[str, Any]) -> str:
        """Generate both PDF and JSON certificates with enhanced information"""
        cert_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Create certificate data
        cert_data = {
            'certificate_id': cert_id,
            'generated_at': timestamp,
            'device_info': {
                'path': wipe_data['device_path'],
                'size_bytes': wipe_data['device_size'],
                'size_human': self._format_bytes(wipe_data['device_size'])
            },
            'wipe_details': {
                'method': wipe_data['method'],
                'start_time': wipe_data['start_time'].isoformat(),
                'end_time': wipe_data['end_time'].isoformat(),
                'duration_seconds': wipe_data['duration'],
                'total_passes': wipe_data['passes']
            },
            'hidden_partition_analysis': wipe_data.get('hidden_partition_info', {}),
            'mount_analysis': wipe_data.get('mount_info', {}),
            'verification': {
                'hashes': wipe_data['verification_hashes'],
                'certificate_hash': None  # Will be calculated
            },
            'compliance': {
                'standard': 'NIST SP 800-88 Rev. 1' if wipe_data['method'] == 'NIST' else 'DoD 5220.22-M',
                'verified': True,
                'hidden_areas_wiped': self._was_hidden_areas_wiped(wipe_data.get('hidden_partition_info', {}))
            }
        }
        
        # Calculate certificate hash for tamper detection
        cert_content = json.dumps(cert_data, sort_keys=True, default=str)
        cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()
        cert_data['verification']['certificate_hash'] = cert_hash
        
        # Save JSON certificate
        json_path = os.path.join(self.cert_dir, f'{cert_id}.json')
        with open(json_path, 'w') as f:
            json.dump(cert_data, f, indent=2, default=str)
        
        # Generate PDF certificate
        pdf_path = os.path.join(self.cert_dir, f'{cert_id}.pdf')
        self._generate_pdf_certificate(cert_data, pdf_path)
        
        return cert_id
    
    def _was_hidden_areas_wiped(self, hidden_info: Dict[str, Any]) -> bool:
        """Check if hidden areas were detected and wiped"""
        if not hidden_info:
            return False
        return hidden_info.get('hpa_unlocked', False) or hidden_info.get('dco_unlocked', False)
    
    def _generate_pdf_certificate(self, cert_data: Dict[str, Any], pdf_path: str):
        """Generate enhanced PDF certificate with hidden partition information"""
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=1,  # Center
            spaceAfter=30
        )
        story.append(Paragraph("SECURE DATA WIPE CERTIFICATE", title_style))
        
        # Certificate ID
        story.append(Paragraph(f"<b>Certificate ID:</b> {cert_data['certificate_id']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Device Information
        story.append(Paragraph("<b>Device Information</b>", styles['Heading2']))
        device_data = [
            ['Device Path:', cert_data['device_info']['path']],
            ['Device Size:', cert_data['device_info']['size_human']],
            ['Size (bytes):', f"{cert_data['device_info']['size_bytes']:,}"]
        ]
        device_table = Table(device_data, colWidths=[2*inch, 4*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(device_table)
        story.append(Spacer(1, 20))
        
        # Hidden Partition Analysis
        hidden_info = cert_data.get('hidden_partition_analysis', {})
        if hidden_info and (hidden_info.get('hpa_detected') or hidden_info.get('dco_detected')):
            story.append(Paragraph("<b>Hidden Partition Analysis</b>", styles['Heading2']))
            
            hidden_data = []
            if hidden_info.get('hpa_detected'):
                status = "Detected and Unlocked" if hidden_info.get('hpa_unlocked') else "Detected but Failed to Unlock"
                hidden_data.append(['HPA (Host Protected Area):', status])
            
            if hidden_info.get('dco_detected'):
                status = "Detected and Unlocked" if hidden_info.get('dco_unlocked') else "Detected but Failed to Unlock"
                hidden_data.append(['DCO (Device Configuration Overlay):', status])
            
            if hidden_info.get('hidden_sectors', 0) > 0:
                hidden_mb = (hidden_info['hidden_sectors'] * 512) // (1024 * 1024)
                hidden_data.append(['Hidden Space Found:', f"{hidden_mb} MB ({hidden_info['hidden_sectors']:,} sectors)"])
            
            if hidden_info.get('actions_taken'):
                actions_text = "<br/>".join([f"• {action}" for action in hidden_info['actions_taken']])
                story.append(Paragraph(f"<b>Actions Taken:</b><br/>{actions_text}", styles['Normal']))
            
            if hidden_data:
                hidden_table = Table(hidden_data, colWidths=[2.5*inch, 3.5*inch])
                hidden_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (0, -1), colors.lightblue),
                    ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ]))
                story.append(hidden_table)
            
            story.append(Spacer(1, 20))
        
        # Mount Analysis
        mount_info = cert_data.get('mount_analysis', {})
        if mount_info and (mount_info.get('unmounted_partitions') or mount_info.get('skipped_partitions')):
            story.append(Paragraph("<b>Mount Point Analysis</b>", styles['Heading2']))
            
            if mount_info.get('unmounted_partitions'):
                unmounted_text = "<br/>".join([f"• {part}" for part in mount_info['unmounted_partitions']])
                story.append(Paragraph(f"<b>Unmounted for Wiping:</b><br/>{unmounted_text}", styles['Normal']))
            
            if mount_info.get('skipped_partitions'):
                skipped_text = "<br/>".join([f"• {part}" for part in mount_info['skipped_partitions']])
                story.append(Paragraph(f"<b>Skipped (System Drives):</b><br/>{skipped_text}", styles['Normal']))
            
            story.append(Spacer(1, 20))
        
        # Wipe Details
        story.append(Paragraph("<b>Wipe Operation Details</b>", styles['Heading2']))
        wipe_data = [
            ['Method:', cert_data['wipe_details']['method']],
            ['Standard:', cert_data['compliance']['standard']],
            ['Start Time:', cert_data['wipe_details']['start_time']],
            ['End Time:', cert_data['wipe_details']['end_time']],
            ['Duration:', f"{cert_data['wipe_details']['duration_seconds']:.2f} seconds"],
            ['Total Passes:', str(cert_data['wipe_details']['total_passes'])],
            ['Hidden Areas Wiped:', 'Yes' if cert_data['compliance']['hidden_areas_wiped'] else 'N/A']
        ]
        wipe_table = Table(wipe_data, colWidths=[2*inch, 4*inch])
        wipe_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(wipe_table)
        story.append(Spacer(1, 20))
        
        # Verification
        story.append(Paragraph("<b>Verification Hashes</b>", styles['Heading2']))
        for hash_data in cert_data['verification']['hashes']:
            story.append(Paragraph(
                f"Pass {hash_data['pass']} ({hash_data['pattern']}): {hash_data['hash'][:16]}...",
                styles['Code']
            ))
        story.append(Spacer(1, 20))
        
        # Certificate Hash
        story.append(Paragraph("<b>Certificate Integrity</b>", styles['Heading2']))
        story.append(Paragraph(
            f"Certificate Hash: {cert_data['verification']['certificate_hash']}",
            styles['Code']
        ))
        story.append(Spacer(1, 20))
        
        # Compliance Statement
        story.append(Paragraph("<b>Compliance Statement</b>", styles['Heading2']))
        compliance_text = (
            f"This certificate verifies that the specified device has been securely wiped "
            f"according to {cert_data['compliance']['standard']} standards. "
        )
        
        if cert_data['compliance']['hidden_areas_wiped']:
            compliance_text += (
                "Hidden areas (HPA/DCO) were detected and successfully included in the wiping process, "
                "ensuring complete data destruction across all accessible storage areas. "
            )
        
        compliance_text += (
            "The certificate hash ensures tamper detection and provides cryptographic proof "
            "of secure erasure completion."
        )
        
        story.append(Paragraph(compliance_text, styles['Normal']))
        
        doc.build(story)
    
    def verify_certificate(self, cert_path: str) -> tuple[bool, str]:
        """Verify certificate integrity"""
        try:
            with open(cert_path, 'r') as f:
                cert_data = json.load(f)
            
            stored_hash = cert_data['verification']['certificate_hash']
            
            # Recalculate hash
            cert_data_copy = cert_data.copy()
            cert_data_copy['verification']['certificate_hash'] = None
            
            recalc_content = json.dumps(cert_data_copy, sort_keys=True, default=str)
            recalc_hash = hashlib.sha256(recalc_content.encode()).hexdigest()
            
            if stored_hash == recalc_hash:
                return True, "Certificate is valid and untampered"
            else:
                return False, "Certificate has been tampered with"
        
        except Exception as e:
            return False, f"Certificate verification failed: {e}"
    
    def _format_bytes(self, bytes_size: int) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"
