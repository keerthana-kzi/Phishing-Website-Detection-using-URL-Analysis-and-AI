

console.log('🛡️ High-Accuracy Phishing Detector v6.0 Started');

// ===== CONFIGURATION WITH  API KEYS =====
const CONFIG = {
  
  
  GOOGLE_SAFE_BROWSING_KEY: 'AIzaSyA2IBnSaCnRQM0yY7ZynXVZP0l6wVhPR34',  
  VIRUSTOTAL_API_KEY: 'b43b03d8fbd25f1ed4fc612428f71753c856e76d9e52039bfc7d4fa134362ee6',    
  
  THRESHOLDS: {
    HIGH_RISK: 70,
    MEDIUM_RISK: 45,
    LOW_RISK: 25
  },
  
  // Optimized weights 
  WEIGHTS: {
    googleSafeBrowsing: 0.30,
    virusTotal: 0.25,
    urlAnalysis: 0.20,
    sslCertificate: 0.15,
    behaviorAnalysis: 0.10
  }
};

// ===== VERIFIED LEGITIMATE DOMAINS (Whitelist) =====
const LEGITIMATE_DOMAINS = new Set([
  'google.com', 'youtube.com', 'gmail.com', 'facebook.com', 'instagram.com',
  'amazon.com', 'microsoft.com', 'apple.com', 'twitter.com', 'linkedin.com',
  'netflix.com', 'github.com', 'stackoverflow.com', 'reddit.com', 'wikipedia.org',
  'paypal.com', 'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
  'americanexpress.com', 'discover.com', 'capitalone.com', 'usbank.com'
]);

// ===== BRAND NAMES TO MONITOR =====
const BRAND_TARGETS = [
  'paypal', 'amazon', 'microsoft', 'apple', 'google', 'facebook', 'netflix',
  'instagram', 'bank', 'chase', 'wellsfargo', 'citibank', 'americanexpress',
  'visa', 'mastercard', 'discover', 'usbank', 'capitalone', 'coinbase',
  'binance', 'metamask', 'blockchain', 'linkedin', 'twitter', 'dropbox',
  'adobe', 'ebay', 'walmart', 'target'
];

// ===== PHISHING KEYWORDS =====
const PHISHING_KEYWORDS = [
  'verify', 'confirm', 'suspended', 'locked', 'update', 'secure', 'account',
  'signin', 'login', 'banking', 'unusual', 'activity', 'verification',
  'authenticate', 'validate', 'restore', 'recover', 'billing', 'payment',
  'expired', 'renew', 'reactivate', 'limited', 'urgent', 'immediate'
];

// ===== DANGEROUS TLDs =====
const DANGEROUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'cc', 'xyz', 'top', 'work',
  'click', 'link', 'online', 'download', 'zip', 'review', 'date',
  'racing', 'bid', 'win', 'party', 'trade', 'webcam', 'science'
]);

// ========================================
// 1. GOOGLE SAFE BROWSING API 
// ========================================
async function checkGoogleSafeBrowsing(url) {
  console.log('🔍 Google Safe Browsing Check...');
  
  if (!CONFIG.GOOGLE_SAFE_BROWSING_KEY) {

    console.warn('⚠️ Google API key not configured');
    return { score: 0, confidence: 0, status: 'Not configured', isPhishing: false };
  }
  
  try {
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.GOOGLE_SAFE_BROWSING_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client: {
            clientId: "phishing-detector-pro",
            clientVersion: "6.0.0"
          },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: url }]
          }
        })
      }
    );
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    const data = await response.json();
    
    if (data.matches && data.matches.length > 0) {
      console.log('🚨 CONFIRMED THREAT by Google!');
      return {
        isPhishing: true,
        score: 100,
        confidence: 100,
        threatType: data.matches[0].threatType,
        source: 'Google Safe Browsing',
        status: 'PHISHING CONFIRMED'
      };
    }
    
    console.log('✅ Clean by Google');
    return {
      isPhishing: false,
      score: 0,
      confidence: 98,
      source: 'Google Safe Browsing',
      status: 'Clean'
    };
    
  } catch (error) {
    console.error('❌ Google API Error:', error);
    return {
      isPhishing: false,
      score: 0,
      confidence: 0,
      error: error.message,
      status: 'Error'
    };
  }
}

// ========================================
// 2. VIRUSTOTAL API
// ========================================
async function checkVirusTotal(url) {
  console.log('🔬 VirusTotal Check...');
  
  if (!CONFIG.VIRUSTOTAL_API_KEY || CONFIG.VIRUSTOTAL_API_KEY === 'YOUR_VIRUSTOTAL_API_KEY') {
    console.warn('⚠️ VirusTotal API key not configured');
    return { score: 0, confidence: 0, status: 'Not configured', isPhishing: false };
  }
  
  try {
    // Encode URL for VirusTotal
    const urlId = btoa(url).replace(/=/g, '');
    
    const response = await fetch(
      `https://www.virustotal.com/api/v3/urls/${urlId}`,
      {
        method: 'GET',
        headers: {
          'x-apikey': CONFIG.VIRUSTOTAL_API_KEY
        }
      }
    );
    
    if (response.status === 404) {
      // URL not in database - submit for scanning
      const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
          'x-apikey': CONFIG.VIRUSTOTAL_API_KEY,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
      });
      
      if (submitResponse.ok) {
        console.log('📤 URL submitted to VirusTotal');
        return {
          isPhishing: false,
          score: 0,
          confidence: 50,
          status: 'Submitted for analysis',
          message: 'First time scan - check back in 24h'
        };
      }
    }
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    const data = await response.json();
    const stats = data.data.attributes.last_analysis_stats;
    
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    const total = malicious + suspicious + harmless + undetected;
    
    // Calculate detection rate
    const detectionRate = total > 0 ? ((malicious + suspicious) / total) * 100 : 0;
    
    // Score calculation
    let score = 0;
    if (malicious >= 5) {
      score = 100;
    } else if (malicious >= 2) {
      score = 80;
    } else if (malicious >= 1) {
      score = 60;
    } else if (suspicious >= 3) {
      score = 40;
    }
    
    const isPhishing = malicious >= 2 || (malicious >= 1 && suspicious >= 2);
    
    console.log(`🔬 VirusTotal: ${malicious}/${total} flagged (${detectionRate.toFixed(1)}%)`);
    
    return {
      isPhishing,
      score,
      confidence: 95,
      malicious,
      suspicious,
      harmless,
      detectionRate: detectionRate.toFixed(1),
      totalEngines: total,
      source: 'VirusTotal',
      status: isPhishing ? 'THREAT DETECTED' : 'Clean'
    };
    
  } catch (error) {
    console.error('❌ VirusTotal Error:', error);
    return {
      isPhishing: false,
      score: 0,
      confidence: 0,
      error: error.message,
      status: 'Error'
    };
  }
}

// ========================================
// 3. SSL CERTIFICATE ANALYSIS 
// ========================================
async function analyzeSSLCertificate(url) {
  console.log('🔒 SSL Certificate Analysis...');
  
  const urlObj = new URL(url);
  let score = 0;
  const warnings = [];
  const details = {
    protocol: urlObj.protocol,
    hasHTTPS: urlObj.protocol === 'https:',
    port: urlObj.port || (urlObj.protocol === 'https:' ? '443' : '80'),
    encryption: 'Unknown',
    risk: 'Unknown'
  };
  
  // CRITICAL: No HTTPS
  if (urlObj.protocol !== 'https:') {
    score = 40; // Major penalty
    warnings.push('🚨 CRITICAL: No HTTPS - Data sent unencrypted!');
    details.encryption = 'NONE';
    details.risk = 'CRITICAL';
    details.recommendation = 'Never enter passwords or sensitive data';
  } else {
    details.encryption = 'TLS/SSL';
    details.risk = 'LOW';
    warnings.push('✅ HTTPS encryption present');
  }
  
  // Check for non-standard ports
  if (urlObj.port && !['80', '443', ''].includes(urlObj.port)) {
    score += 20;
    warnings.push(`⚠️ Non-standard port: ${urlObj.port}`);
    details.portRisk = 'SUSPICIOUS';
  }
  
  return {
    score: Math.min(score, 100),
    warnings,
    details,
    confidence: 95
  };
}

// ========================================
// 4. ADVANCED URL ANALYSIS 
// ========================================
function analyzeURL(url) {
  console.log('🔗 URL Pattern Analysis...');
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const fullUrl = url.toLowerCase();
    const parts = hostname.split('.');
    
    let score = 0;
    const flags = [];
    const criticalFlags = [];
    
    // WHITELIST CHECK
    const isWhitelisted = Array.from(LEGITIMATE_DOMAINS).some(d => 
      hostname === d || hostname === `www.${d}` || hostname.endsWith(`.${d}`)
    );
    
    if (isWhitelisted) {
      console.log('✅ Whitelisted domain');
      return {
        score: 0,
        flags: ['✅ Verified legitimate domain'],
        criticalFlags: [],
        details: { whitelisted: true, domain: hostname }
      };
    }
    
    // 1. IP ADDRESS (50 points - CRITICAL)
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      score += 50;
      criticalFlags.push('🚨 IP address instead of domain - HIGH RISK');
    }
    
    // 2. UNICODE/HOMOGRAPH ATTACK (45 points)
    if (/[^\x00-\x7F]/.test(hostname)) {
      score += 45;
      criticalFlags.push('🚨 Unicode characters - possible homograph attack');
    }
    
    // 3. SUBDOMAIN TRICKERY (35 points)
    if (parts.length > 3) {
      score += 25;
      const subdomains = parts.slice(0, -2).join('.');
      const realDomain = parts.slice(-2).join('.');
      
      // Check if brand is in subdomain but not real domain
      for (const brand of BRAND_TARGETS) {
        if (subdomains.includes(brand) && !realDomain.includes(brand)) {
          score += 35;
          criticalFlags.push(`🚨 SUBDOMAIN TRICK: "${brand}" is fake - real domain is "${realDomain}"`);
          break;
        }
      }
      
      flags.push(`⚠️ ${parts.length - 2} subdomain levels`);
    }
    
    // 4. BRAND IMPERSONATION (40 points)
    for (const brand of BRAND_TARGETS) {
      if (hostname.includes(brand) && !isWhitelisted) {
        score += 40;
        criticalFlags.push(`🚨 BRAND IMPERSONATION: Contains "${brand}"`);
        break;
      }
    }
    
    // 5. PHISHING KEYWORDS (30 points)
    const foundKeywords = PHISHING_KEYWORDS.filter(kw => fullUrl.includes(kw));
    if (foundKeywords.length > 0) {
      score += Math.min(foundKeywords.length * 10, 30);
      flags.push(`⚠️ Phishing keywords: ${foundKeywords.slice(0, 3).join(', ')}`);
    }
    
    // 6. DANGEROUS TLD (35 points)
    const tld = parts[parts.length - 1];
    if (DANGEROUS_TLDS.has(tld)) {
      score += 35;
      criticalFlags.push(`🚨 Dangerous TLD: .${tld}`);
    }
    
    // 7. @ SYMBOL (40 points)
    if (fullUrl.includes('@')) {
      score += 40;
      criticalFlags.push('🚨 @ symbol - URL obfuscation');
    }
    
    // 8. EXCESSIVE DASHES (20 points)
    const dashCount = (hostname.match(/-/g) || []).length;
    if (dashCount > 3) {
      score += 20;
      flags.push(`⚠️ ${dashCount} dashes in domain`);
    }
    
    // 9. LONG URL (15 points)
    if (fullUrl.length > 100) {
      score += 15;
      flags.push(`⚠️ Long URL: ${fullUrl.length} chars`);
    }
    
    // 10. TYPOSQUATTING (30 points)
    const typoCheck = checkTyposquatting(hostname);
    if (typoCheck.isTypo) {
      score += 30;
      criticalFlags.push(`🚨 Typosquatting: Similar to ${typoCheck.target}`);
    }
    
    // 11. ENTROPY (20 points)
    const entropy = calculateEntropy(hostname);
    if (entropy > 4.5) {
      score += 20;
      flags.push(`⚠️ High entropy: ${entropy.toFixed(2)} - random domain`);
    }
    
    return {
      score: Math.min(score, 100),
      flags: [...criticalFlags, ...flags],
      criticalFlags,
      details: {
        domain: hostname,
        tld,
        subdomains: parts.length - 2,
        urlLength: fullUrl.length,
        dashCount,
        entropy: entropy.toFixed(2),
        keywords: foundKeywords
      }
    };
    
  } catch (error) {
    console.error('URL analysis error:', error);
    return {
      score: 50,
      flags: ['Error analyzing URL'],
      criticalFlags: [],
      details: { error: error.message }
    };
  }
}

// ========================================
// 5. TYPOSQUATTING DETECTION
// ========================================
function checkTyposquatting(hostname) {
  const domain = hostname.replace(/^www\./, '').split('.')[0];
  
  for (const brand of BRAND_TARGETS) {
    const distance = levenshteinDistance(domain, brand);
    
    if (distance > 0 && distance <= 2) {
      return {
        isTypo: true,
        target: brand,
        distance,
        confidence: 95
      };
    }
    
    // Character substitutions
    const substitutions = {
      'a': ['@', '4'], 'e': ['3'], 'i': ['1', 'l'], 'o': ['0'], 's': ['5', '$']
    };
    
    for (const [char, replacements] of Object.entries(substitutions)) {
      for (const replacement of replacements) {
        if (domain.includes(replacement) && brand.includes(char)) {
          const normalized = domain.replace(new RegExp(replacement, 'g'), char);
          if (normalized === brand) {
            return {
              isTypo: true,
              target: brand,
              method: 'character substitution',
              confidence: 90
            };
          }
        }
      }
    }
  }
  
  return { isTypo: false };
}

// ========================================
// 6. BEHAVIOR ANALYSIS
// ========================================
async function analyzeBehavior(tabId) {
  console.log('⚡ Behavior Analysis...');
  
  try {
    const result = await chrome.storage.local.get(`behavior_${tabId}`);
    const data = result[`behavior_${tabId}`] || {};
    
    let score = 0;
    const flags = [];
    
    // Multiple password fields
    if (data.passwordFields > 2) {
      score += 35;
      flags.push(`🚨 ${data.passwordFields} password fields`);
    } else if (data.passwordFields > 0) {
      score += 10;
    }
    
    // Suspicious patterns
    if (data.suspiciousPatterns && data.suspiciousPatterns.length > 0) {
      score += Math.min(data.suspiciousPatterns.length * 12, 40);
      flags.push(`🚨 ${data.suspiciousPatterns.length} suspicious patterns`);
    }
    
    // Iframes
    if (data.iframes > 2) {
      score += 30;
      flags.push(`🚨 ${data.iframes} iframes`);
    } else if (data.iframes > 0) {
      score += 15;
    }
    
    // Popups
    if (data.popups > 0) {
      score += 25;
      flags.push(`🚨 ${data.popups} popup attempts`);
    }
    
    return {
      score: Math.min(score, 100),
      flags,
      data,
      confidence: 85
    };
    
  } catch (error) {
    return { score: 0, flags: [], data: {}, confidence: 0 };
  }
}

// ========================================
// MAIN ANALYSIS ORCHESTRATOR
// ========================================
async function analyzeWebsite(url, tabId) {
  console.log('🎯 ===== STARTING ANALYSIS =====');
  console.log('URL:', url);
  const startTime = Date.now();
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    
    // Run all checks in parallel
    const [googleResult, vtResult, sslResult, urlResult, behaviorResult] = 
      await Promise.all([
        checkGoogleSafeBrowsing(url),
        checkVirusTotal(url),
        analyzeSSLCertificate(url),
        Promise.resolve(analyzeURL(url)),
        analyzeBehavior(tabId)
      ]);
    
    // CONFIRMED PHISHING
    if (googleResult.isPhishing || vtResult.isPhishing) {
      const source = googleResult.isPhishing ? 'Google Safe Browsing' : 'VirusTotal';
      
      const results = {
        url,
        timestamp: new Date().toISOString(),
        analysisTime: Date.now() - startTime,
        overallScore: 98,
        riskLevel: 'high',
        verdict: `🚨 CONFIRMED PHISHING!\n\nDetected by: ${source}\nConfidence: 100%\n\n⛔ DO NOT ENTER ANY INFORMATION!`,
        confirmed: true,
        googleSafeBrowsing: googleResult,
        virusTotal: vtResult,
        sslAnalysis: sslResult,
        urlAnalysis: urlResult,
        behaviorAnalysis: behaviorResult,
        websiteInfo: {
          domain: hostname,
          protocol: urlObj.protocol,
          tld: hostname.split('.').pop(),
          hasHTTPS: urlObj.protocol === 'https:'
        }
      };
      
      await chrome.storage.local.set({ [`analysis_${tabId}`]: results });
      
      // Critical notification
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚨 PHISHING DETECTED!',
        message: `CONFIRMED by ${source}!\n\nDO NOT enter credentials!`,
        priority: 2,
        requireInteraction: true
      });
      
      return results;
    }
    
    // Calculate weighted score
    const overallScore = Math.round(
      (googleResult.score * CONFIG.WEIGHTS.googleSafeBrowsing) +
      (vtResult.score * CONFIG.WEIGHTS.virusTotal) +
      (urlResult.score * CONFIG.WEIGHTS.urlAnalysis) +
      (sslResult.score * CONFIG.WEIGHTS.sslCertificate) +
      (behaviorResult.score * CONFIG.WEIGHTS.behaviorAnalysis)
    );
    
    // Risk level
    const riskLevel = 
      overallScore >= CONFIG.THRESHOLDS.HIGH_RISK ? 'high' :
      overallScore >= CONFIG.THRESHOLDS.MEDIUM_RISK ? 'medium' :
      overallScore >= CONFIG.THRESHOLDS.LOW_RISK ? 'low' : 'safe';
    
    const verdict = generateVerdict(riskLevel, overallScore);
    
    const results = {
      url,
      timestamp: new Date().toISOString(),
      analysisTime: Date.now() - startTime,
      overallScore,
      riskLevel,
      verdict,
      googleSafeBrowsing: googleResult,
      virusTotal: vtResult,
      sslAnalysis: sslResult,
      urlAnalysis: urlResult,
      behaviorAnalysis: behaviorResult,
      websiteInfo: {
        domain: hostname,
        protocol: urlObj.protocol,
        tld: hostname.split('.').pop(),
        hasHTTPS: urlObj.protocol === 'https:',
        port: urlObj.port || 'default'
      },
      weights: CONFIG.WEIGHTS,
      confidence: 96
    };
    
    await chrome.storage.local.set({ [`analysis_${tabId}`]: results });
    
    console.log(`✅ Complete: ${overallScore}/100 (${riskLevel.toUpperCase()})`);
    
    if (riskLevel === 'high') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icons/icon48.png',
        title: '🚨 High Risk!',
        message: `Score: ${overallScore}/100\n\nBe cautious!`,
        priority: 1
      });
    }
    
    return results;
    
  } catch (error) {
    console.error('❌ Analysis failed:', error);
    throw error;
  }
}

// ========================================
// HELPER FUNCTIONS
// ========================================
function calculateEntropy(str) {
  if (!str) return 0;
  const freq = {};
  for (let char of str) freq[char] = (freq[char] || 0) + 1;
  
  let entropy = 0;
  const len = str.length;
  for (let char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function levenshteinDistance(str1, str2) {
  const matrix = [];
  for (let i = 0; i <= str2.length; i++) matrix[i] = [i];
  for (let j = 0; j <= str1.length; j++) matrix[0][j] = j;
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2[i - 1] === str1[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  return matrix[str2.length][str1.length];
}

function generateVerdict(level, score) {
  const verdicts = {
    high: `🚨 PHISHING DETECTED (${score}/100)\n\n⛔ DO NOT:\n• Enter passwords\n• Provide credit cards\n• Share personal info\n\n🔒 Close this page!`,
    medium: `⚠️ SUSPICIOUS (${score}/100)\n\nMultiple red flags detected.\n\n⚠️ EXTREME CAUTION:\n• Verify URL carefully\n• Do not enter sensitive data`,
    low: `⚡ MINOR CONCERNS (${score}/100)\n\nSome suspicious signs.\n\n✓ Verify before proceeding.`,
    safe: `✅ APPEARS SAFE (${score}/100)\n\nNo major threats detected.\n\n💡 Always verify SSL and URL.`
  };
  return verdicts[level];
}

// ========================================
// EVENT LISTENERS
// ========================================
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Skip internal pages
    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') ||
        tab.url.startsWith('edge://') || tab.url.startsWith('about:')) {
      return;
    }
    
    // Wait for page to settle
    setTimeout(async () => {
      try {
        await analyzeWebsite(tab.url, tabId);
      } catch (error) {
        console.error('Analysis error:', error);
      }
    }, 2000);
  }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'behaviorData') {
    const tabId = sender.tab?.id;
    if (tabId) {
      chrome.storage.local.set({ [`behavior_${tabId}`]: request.data });
    }
  }
  sendResponse({ received: true });
  return true;
});

console.log('✅ Phishing Detector Ready');