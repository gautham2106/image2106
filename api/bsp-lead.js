// Vercel API Route for BSP Lead Capture
// Place this file at: api/bsp-lead.js

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// --- BSP Lead Storage ---
// Simple in-memory storage for BSP leads (resets on server restart)
const bspLeadStore = {
  latest: null,           // Most recent lead
  byPhone: new Map(),     // Map phone -> lead data
  bySession: new Map(),   // Map session/chat_id -> phone
  recent: []              // Array of recent leads (max 100)
};

// Store BSP lead data
function storeBspLead(leadData) {
  const phoneNumber = leadData.phoneNumber || leadData.chat_id;
  const timestamp = new Date().toISOString();
  
  const enrichedLead = {
    ...leadData,
    phoneNumber,
    timestamp,
    id: `${phoneNumber}-${Date.now()}`
  };
  
  // Store as latest
  bspLeadStore.latest = enrichedLead;
  
  // Store by phone number
  if (phoneNumber) {
    bspLeadStore.byPhone.set(phoneNumber, enrichedLead);
    
    // Store session mapping
    if (leadData.chatId || leadData.chat_id) {
      bspLeadStore.bySession.set(leadData.chatId || leadData.chat_id, phoneNumber);
    }
  }
  
  // Add to recent leads (keep only last 100)
  bspLeadStore.recent.unshift(enrichedLead);
  if (bspLeadStore.recent.length > 100) {
    bspLeadStore.recent = bspLeadStore.recent.slice(0, 100);
  }
  
  console.log('📍 BSP Lead stored:', {
    phone: phoneNumber,
    name: leadData.firstName || leadData.first_name,
    totalStored: bspLeadStore.byPhone.size,
    recentCount: bspLeadStore.recent.length
  });
  
  return enrichedLead;
}

// Get BSP lead data
function getBspLead(identifier = 'latest') {
  if (identifier === 'latest') {
    return bspLeadStore.latest;
  }
  
  // Try to get by phone number
  if (bspLeadStore.byPhone.has(identifier)) {
    return bspLeadStore.byPhone.get(identifier);
  }
  
  // Try to get by session/chat_id
  if (bspLeadStore.bySession.has(identifier)) {
    const phone = bspLeadStore.bySession.get(identifier);
    return bspLeadStore.byPhone.get(phone);
  }
  
  return null;
}

// Optional: Persist to database (implement based on your needs)
async function persistBspLead(leadData) {
  try {
    // Example: Save to Supabase
    // const { createClient } = require('@supabase/supabase-js');
    // const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);
    // await supabase.from('bsp_leads').upsert({
    //   phone_number: leadData.phoneNumber,
    //   first_name: leadData.firstName || leadData.first_name,
    //   email: leadData.email,
    //   chat_id: leadData.chatId || leadData.chat_id,
    //   subscriber_id: leadData.subscriberId,
    //   user_message: leadData.userMessage || leadData.user_message,
    //   postback_id: leadData.postbackId || leadData.postbackid,
    //   created_at: leadData.timestamp
    // });
    
    // Example: Save to Google Sheets
    // await appendToGoogleSheet([
    //   leadData.phoneNumber,
    //   leadData.firstName || leadData.first_name,
    //   leadData.email,
    //   leadData.userMessage || leadData.user_message,
    //   leadData.timestamp
    // ]);
    
    // Example: Send to CRM API
    // await fetch('https://your-crm.com/api/leads', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({
    //     phone: leadData.phoneNumber,
    //     name: leadData.firstName || leadData.first_name,
    //     email: leadData.email,
    //     message: leadData.userMessage || leadData.user_message,
    //     timestamp: leadData.timestamp
    //   })
    // });
    
    console.log('💾 BSP lead persistence ready (implement your preferred method)');
    return true;
  } catch (error) {
    console.error('Failed to persist BSP lead:', error);
    return false;
  }
}

// --- BSP Lead Capture Handler ---
async function handleBspLead(req, res) {
  console.log('=== BSP LEAD WEBHOOK ===');
  console.log('Method:', req.method);
  console.log('Headers:', req.headers);
  console.log('Body:', JSON.stringify(req.body, null, 2));
  
  try {
    // Validate required fields
    if (!req.body.phoneNumber && !req.body.chat_id) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_PHONE_NUMBER',
        message: 'phoneNumber or chat_id is required',
        receivedData: req.body
      });
    }

    if (!req.body.firstName && !req.body.first_name) {
      return res.status(400).json({
        success: false,
        error: 'MISSING_FIRST_NAME',
        message: 'firstName or first_name is required',
        receivedData: req.body
      });
    }
    
    // Handle both BSP structures:
    // 1. Your planned structure: { phoneNumber, firstName }
    // 2. Alternative structure: { chat_id, first_name }
    
    const leadData = {
      phoneNumber: req.body.phoneNumber || req.body.chat_id,
      firstName: req.body.firstName || req.body.first_name,
      email: req.body.email,
      chatId: req.body.chatId || req.body.chat_id,
      subscriberId: req.body.subscriberId,
      userMessage: req.body.user_message || req.body.userMessage,
      postbackId: req.body.postbackid || req.body.postbackId,
      source: 'BSP',
      // Include any other fields that might be useful
      ...req.body
    };
    
    console.log('=== EXTRACTED LEAD DATA ===');
    console.log('Phone Number:', leadData.phoneNumber);
    console.log('First Name:', leadData.firstName);
    console.log('Email:', leadData.email);
    console.log('Chat ID:', leadData.chatId);
    console.log('Subscriber ID:', leadData.subscriberId);
    console.log('User Message:', leadData.userMessage);
    console.log('Postback ID:', leadData.postbackId);

    console.log('✅ LEAD CAPTURED SUCCESSFULLY');
    
    // Store the lead data in memory
    const storedLead = storeBspLead(leadData);
    
    // Optionally persist to database
    await persistBspLead(storedLead);
    
    return res.status(200).json({
      success: true,
      message: 'Lead received and processed successfully',
      data: {
        id: storedLead.id,
        phoneNumber: storedLead.phoneNumber,
        firstName: storedLead.firstName,
        email: storedLead.email,
        chatId: storedLead.chatId,
        subscriberId: storedLead.subscriberId,
        userMessage: storedLead.userMessage,
        stored: true,
        source: 'BSP'
      },
      timestamp: storedLead.timestamp
    });

  } catch (error) {
    console.error('BSP lead processing error:', error);
    return res.status(500).json({ 
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
}

// --- Debug endpoint to check BSP lead storage ---
async function handleDebugLeads(req, res) {
  console.log('=== DEBUG LEADS ENDPOINT ===');
  
  const debugInfo = {
    latest: bspLeadStore.latest,
    totalStored: bspLeadStore.byPhone.size,
    recentCount: bspLeadStore.recent.length,
    phoneNumbers: Array.from(bspLeadStore.byPhone.keys()),
    recentLeads: bspLeadStore.recent.slice(0, 10).map(lead => ({
      phone: lead.phoneNumber,
      name: lead.firstName,
      timestamp: lead.timestamp,
      id: lead.id,
      source: lead.source
    })),
    sessionMappings: Array.from(bspLeadStore.bySession.entries())
  };
  
  console.log('Debug info:', JSON.stringify(debugInfo, null, 2));
  
  return res.status(200).json({
    success: true,
    message: 'BSP Lead Storage Debug Info',
    data: debugInfo,
    timestamp: new Date().toISOString()
  });
}

// --- Get specific lead endpoint ---
async function handleGetLead(req, res) {
  const { identifier } = req.query;
  
  if (!identifier) {
    return res.status(400).json({
      success: false,
      error: 'MISSING_IDENTIFIER',
      message: 'identifier query parameter is required (phone number, chat_id, or "latest")'
    });
  }
  
  const lead = getBspLead(identifier);
  
  if (!lead) {
    return res.status(404).json({
      success: false,
      error: 'LEAD_NOT_FOUND',
      message: `No lead found for identifier: ${identifier}`
    });
  }
  
  return res.status(200).json({
    success: true,
    message: 'Lead found',
    data: lead,
    timestamp: new Date().toISOString()
  });
}

// --- Main API Handler ---
export default async function handler(req, res) {
  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.status(200);
    Object.entries(corsHeaders).forEach(([key, value]) => {
      res.setHeader(key, value);
    });
    return res.end();
  }

  // Set CORS headers for all responses
  Object.entries(corsHeaders).forEach(([key, value]) => {
    res.setHeader(key, value);
  });

  try {
    // Route: POST /api/bsp-lead - Create/Store lead
    if (req.method === 'POST') {
      return handleBspLead(req, res);
    }

    // Route: GET /api/bsp-lead?debug=true - Debug lead storage
    if (req.method === 'GET' && req.query.debug === 'true') {
      return handleDebugLeads(req, res);
    }

    // Route: GET /api/bsp-lead?identifier=<phone|chat_id|latest> - Get specific lead
    if (req.method === 'GET' && req.query.identifier) {
      return handleGetLead(req, res);
    }

    // Route: GET /api/bsp-lead - Health check and usage info
    if (req.method === 'GET') {
      return res.status(200).json({
        success: true,
        message: 'BSP Lead Capture API',
        endpoints: {
          'POST /api/bsp-lead': 'Store a new lead',
          'GET /api/bsp-lead?debug=true': 'Debug lead storage',
          'GET /api/bsp-lead?identifier=<phone|latest>': 'Get specific lead',
          'GET /api/bsp-lead': 'This help message'
        },
        expectedPayload: {
          phoneNumber: '#LEAD_USER_CHAT_ID#',
          firstName: '#LEAD_USER_FIRST_NAME#',
          email: 'optional',
          chatId: 'optional',
          subscriberId: 'optional'
        },
        timestamp: new Date().toISOString()
      });
    }

    // Method not allowed
    return res.status(405).json({ 
      success: false,
      error: 'METHOD_NOT_ALLOWED',
      message: `Method ${req.method} not allowed`,
      allowedMethods: ['GET', 'POST', 'OPTIONS']
    });

  } catch (error) {
    console.error('API Handler Error:', error);
    return res.status(500).json({
      success: false,
      error: 'INTERNAL_SERVER_ERROR',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
}
