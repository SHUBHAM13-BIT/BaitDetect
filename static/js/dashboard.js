// BaitDetect - Cybersecurity Dashboard & Interaction Engine

document.addEventListener("DOMContentLoaded", function () {
  initDropZone();
  initFormHandler();
  initSyntheticSampleButtons();
});

// Drag and Drop File Upload
function initDropZone() {
  const dropZone = document.getElementById("emailDropZone");
  const fileInput = document.getElementById("emailFileInput");
  const fileInfo = document.getElementById("selectedFileInfo");

  if (!dropZone || !fileInput) return;

  dropZone.addEventListener("click", () => fileInput.click());

  dropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    dropZone.classList.add("dragover");
  });

  dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("dragover");
  });

  dropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    dropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      displaySelectedFile(fileInput.files[0]);
    }
  });

  fileInput.addEventListener("change", () => {
    if (fileInput.files.length > 0) {
      displaySelectedFile(fileInput.files[0]);
    }
  });

  function displaySelectedFile(file) {
    if (fileInfo) {
      fileInfo.innerHTML = `
        <div class="alert alert-info py-2 px-3 mt-2 d-flex align-items-center justify-content-between" style="background-color: rgba(6,182,212,0.1); border-color: var(--accent-cyan); color: #fff;">
          <span><i class="bi bi-file-earmark-check me-2"></i><strong>${file.name}</strong> (${formatBytes(file.size)})</span>
          <button type="button" class="btn-close btn-close-white" onclick="clearSelectedFile()"></button>
        </div>
      `;
    }
  }
}

function clearSelectedFile() {
  const fileInput = document.getElementById("emailFileInput");
  const fileInfo = document.getElementById("selectedFileInfo");
  if (fileInput) fileInput.value = "";
  if (fileInfo) fileInfo.innerHTML = "";
}

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Form Submission with Loading Spinner
function initFormHandler() {
  const form = document.getElementById("analysisForm");
  const submitBtn = document.getElementById("submitAnalysisBtn");
  const loadingIndicator = document.getElementById("analysisLoadingState");
  const errorAlert = document.getElementById("analysisErrorAlert");

  if (!form) return;

  form.addEventListener("submit", function (e) {
    const rawText = document.getElementById("rawEmailContent")?.value.trim();
    const fileInput = document.getElementById("emailFileInput");
    const hasFile = fileInput && fileInput.files.length > 0;

    if (!rawText && !hasFile) {
      e.preventDefault();
      showError("Please enter email text, paste headers, or upload an email file (.eml, .txt).");
      return;
    }

    if (submitBtn) submitBtn.disabled = true;
    if (loadingIndicator) loadingIndicator.classList.remove("d-none");
    if (errorAlert) errorAlert.classList.add("d-none");
  });
}

function showError(msg) {
  const errorAlert = document.getElementById("analysisErrorAlert");
  if (errorAlert) {
    errorAlert.textContent = msg;
    errorAlert.classList.remove("d-none");
  } else {
    alert(msg);
  }
}

// Synthetic Email Samples for Quick Testing
const SYNTHETIC_SAMPLES = {
  credential_phish: `From: "PayPal Security Center" <service@secure-paypal-alert-update.xyz>
To: target-victim@company.com
Reply-To: security-reply@gmail.com
Subject: URGENT: Your PayPal Account Has Been Suspended - Verify Identity Immediately
Date: Tue, 24 Nov 2026 12:00:00 +0000
Message-ID: <unauthorized-login-alert@suspicious.com>
Authentication-Results: mx.google.com; spf=fail (google.com: domain of service@secure-paypal-alert-update.xyz does not designate permitted sender); dkim=fail; dmarc=fail
Received: from unknown (HELO mail.scam-relay.net) [198.51.100.45] by mx.company.com; Tue, 24 Nov 2026 12:01:00 +0000

Dear Customer,

We detected unauthorized login attempts to your PayPal account from an unrecognized IP address.
To protect your funds, your account will be permanently deactivated within 24 hours unless you verify your identity.

Click here to verify your account immediately:
http://198.51.100.45/paypal-login/verify.php?redirect=http://login.secure.paypal.com.evil.xyz

Failure to comply will result in account closure.

Sincerely,
PayPal Security & Risk Management Team`,

  bec_wire: `From: "Robert Vance (CEO)" <ceo.executive.urgent@fastmail.com>
To: finance-team@company.com
Reply-To: ceo-private-desk@gmail.com
Subject: Urgent Confidential Request - Wire Transfer Needed Today
Date: Tue, 24 Nov 2026 14:15:00 +0000
Message-ID: <92837492837492@fastmail.com>
Authentication-Results: mx.google.com; spf=softfail; dkim=none; dmarc=fail

Hi Team,

Are you at your desk right now?

I am currently in an executive board meeting and cannot take calls. We have an urgent confidential acquisition payment of $48,500 that must be processed via wire transfer today before 4:00 PM.

Please confirm you can handle this wire immediately so I can send the vendor banking details. Keep this strictly confidential until the official press release.

Regards,
Robert Vance
Chief Executive Officer`,

  malware_invoice: `From: "Accounts Receivable - Office Supplies Ltd" <billing@supplier-portal-docs.com>
To: accounting@company.com
Subject: OVERDUE INVOICE #INV-98231 - Immediate Payment Required
Date: Tue, 24 Nov 2026 09:30:00 +0000
Message-ID: <inv98231@supplier-portal-docs.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass

Dear Valued Client,

Your payment for invoice #INV-98231 is now 30 days overdue. A late fee has been assessed.
Please inspect the attached detailed invoice calculation sheet:

Attachment: Invoice_Overdue_Statement.pdf.exe (Size: 450 KB, SHA-256: 3a7f8e81c741492d...)

Please remit payment within 48 hours to avoid credit reporting.

Regards,
Billing Dept`,

  legitimate_newsletter: `From: "GitHub" <notifications@github.com>
To: developer@company.com
Reply-To: support@github.com
Return-Path: <bounces@github.com>
Subject: [GitHub] A new security advisory was published for your repository
Date: Tue, 24 Nov 2026 10:00:00 +0000
Message-ID: <gh-advisory-2026-98124@github.com>
Authentication-Results: mx.google.com; spf=pass (google.com: domain of bounces@github.com designates 192.30.252.0 as permitted sender); dkim=pass header.i=@github.com; dmarc=pass (p=REJECT)
Received: from mail-relay.github.com [192.30.252.12] by mx.google.com; Tue, 24 Nov 2026 10:00:02 +0000

Hi Developer,

A new Dependabot security alert was detected in your repository.
Package: express (severity: Moderate).

You can review the security advisory details and suggested update pull requests at:
https://github.com/security/advisories/GHSA-example-test

You are receiving this email because you are watching this repository.

GitHub, Inc. • 88 Colin P Kelly Jr St, San Francisco, CA 94107`
};

function initSyntheticSampleButtons() {
  window.loadSampleEmail = function (sampleKey) {
    const textarea = document.getElementById("rawEmailContent");
    if (textarea && SYNTHETIC_SAMPLES[sampleKey]) {
      textarea.value = SYNTHETIC_SAMPLES[sampleKey];
      clearSelectedFile();
      // Scroll to textarea
      textarea.scrollIntoView({ behavior: 'smooth', block: 'center' });
      textarea.focus();
    }
  };
}

// Copy Text Helper
function copyText(elementId, btnElement) {
  const el = document.getElementById(elementId);
  if (!el) return;
  const text = el.innerText || el.value;
  navigator.clipboard.writeText(text).then(() => {
    const original = btnElement.innerHTML;
    btnElement.innerHTML = `<i class="bi bi-check-lg"></i> Copied!`;
    setTimeout(() => { btnElement.innerHTML = original; }, 2000);
  });
}
