// Vercel Node.js API Route for Processing Image Generation Jobs
//This is new deploy
// Place this file at: api/process-job.js

import { createClient } from '@supabase/supabase-js';

// --- CORS Headers ---
const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
};

// WhatsApp API config
const WHATSAPP_TOKEN = process.env.WHATSAPP_TOKEN;
const WHATSAPP_PHONE_NUMBER_ID = process.env.WHATSAPP_PHONE_NUMBER_ID;
const WHATSAPP_API_VERSION = process.env.WHATSAPP_API_VERSION || 'v23.0';

// Supabase config
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_KEY;
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || 'generated-images';

// Simple prompt creation function
function createSimplePrompt(productCategory, sceneDescription = null, priceOverlay = null) {
  let prompt = `Create a professional product photo of this ${productCategory}.`;
  
  if (sceneDescription && sceneDescription.trim()) {
    prompt += ` Show it in this setting: ${sceneDescription}.`;
  } else {
    prompt += ` Use a clean, professional background that complements the product.`;
  }
  
  if (priceOverlay && priceOverlay.trim()) {
    prompt += ` Include the price "${priceOverlay}" as a stylish overlay on the image.`;
  }
  
  prompt += ` Make it look like a high-quality commercial product photo suitable for marketing and sales.`;
  
  return prompt;
}

// Upload generated image to Supabase Storage
async function uploadGeneratedImageToSupabase(base64Data, mimeType) {
  console.log('📤 Uploading to Supabase Storage...');
  
  if (!SUPABASE_URL || !SUPABASE_KEY) {
    throw new Error('Missing SUPABASE_URL or SUPABASE_KEY environment variables');
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
  
  const buffer = Buffer.from(base64Data, 'base64');
  const ext = (mimeType && mimeType.split('/')[1]) || 'jpg';
  const filename = `generated-${Date.now()}.${ext}`;

  console.log('📁 Uploading file:', filename, 'to bucket:', SUPABASE_BUCKET);

  const { data, error } = await supabase.storage
    .from(SUPABASE_BUCKET)
    .upload(filename, buffer, {
      contentType: mimeType || 'image/jpeg',
      cacheControl: '3600',
      upsert: false
    });

  if (error) {
    console.error('❌ Supabase upload error:', error);
    throw new Error(`Supabase upload failed: ${error.message}`);
  }

  console.log('✅ File uploaded successfully:', data);

  // Get public URL
  const { data: publicUrlData } = supabase.storage
    .from(SUPABASE_BUCKET)
    .getPublicUrl(filename);

  if (!publicUrlData?.publicUrl) {
    throw new Error('Failed to get public URL from Supabase');
  }

  console.log('🔗 Public URL generated:', publicUrlData.publicUrl);
  return publicUrlData.publicUrl;
}

// Generate image using Gemini API
async function generateImageFromAi(productImageBase64, productCategory, sceneDescription = null, priceOverlay = null) {
  console.log('=== GENERATE IMAGE FROM AI ===');
  console.log('Parameters:');
  console.log('- productImageBase64 length:', productImageBase64 ? productImageBase64.length : 0);
  console.log('- productCategory:', productCategory || 'MISSING');
  console.log('- sceneDescription:', sceneDescription || 'not provided');
  console.log('- priceOverlay:', priceOverlay || 'not provided');
  
  if (!productImageBase64 || typeof productImageBase64 !== 'string') {
    throw new Error("Product image data is missing or invalid");
  }
  
  if (!productCategory || typeof productCategory !== 'string') {
    throw new Error("Product category is required");
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    throw new Error("Missing GEMINI_API_KEY environment variable");
  }

  console.log("Step 1: Cleaning base64 data...");
  
  let cleanBase64 = productImageBase64;
  if (productImageBase64.startsWith('data:')) {
    const base64Index = productImageBase64.indexOf(',');
    if (base64Index !== -1) {
      cleanBase64 = productImageBase64.substring(base64Index + 1);
      console.log("✅ Data URL prefix removed, new length:", cleanBase64.length);
    }
  }

  console.log("Step 2: Creating simple prompt...");
  
  const simplePrompt = createSimplePrompt(productCategory, sceneDescription, priceOverlay);
  console.log("Simple prompt:", simplePrompt);

  console.log("Step 3: Sending to Gemini API...");

  const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image-preview:generateContent?key=${apiKey}`;

  const requestBody = {
    contents: [
      {
        parts: [
          { text: simplePrompt },
          {
            inlineData: {
              mimeType: "image/jpeg",
              data: cleanBase64
            }
          }
        ]
      }
    ],
    generationConfig: {
      temperature: 0.8,
      maxOutputTokens: 1024,
      topP: 0.9,
      topK: 40
    }
  };

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody)
    });

    console.log("Response status:", response.status);

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Gemini API error response:", errorText);
      throw new Error(`Gemini API failed (${response.status}): ${errorText}`);
    }

    const responseData = await response.json();
    console.log("✅ Gemini API response received");

    const candidate = responseData?.candidates?.[0];
    if (!candidate?.content?.parts) {
      throw new Error("No response parts found in Gemini API response");
    }

    console.log("Step 4: Processing generated image...");

    for (const part of candidate.content.parts) {
      if (part.inlineData) {
        const generatedMimeType = part.inlineData.mimeType;
        const generatedBase64 = part.inlineData.data;
        console.log("✅ Image generated successfully");
        
        console.log("Step 5: Uploading generated image to Supabase...");
        try {
          const publicUrl = await uploadGeneratedImageToSupabase(generatedBase64, generatedMimeType);
          console.log("✅ Generated image uploaded to Supabase:", publicUrl);
          return publicUrl;
        } catch (uploadError) {
          console.error("Failed to upload generated image:", uploadError);
          console.log("⚠️ Fallback: returning base64 data URL");
          return `data:${generatedMimeType};base64,${generatedBase64}`;
        }
      }
    }

    const textPart = candidate.content.parts.find((p) => p.text);
    if (textPart) {
      throw new Error(`Model returned text instead of image: ${textPart.text}`);
    }

    throw new Error("No image data found in Gemini API response");
  } catch (error) {
    console.error('❌ Error in generateImageFromAi:', error);
    throw error;
  }
}

// Create personalized image caption
function createImageCaption(productCategory, priceOverlay, userPhone) {
  let caption = `Here's your enhanced ${productCategory}`;
  
  // Price if provided
  if (priceOverlay && priceOverlay.trim()) {
    caption += ` — ${priceOverlay.trim()}`;
  }
  
  caption += ' image! 🎨✨';
  
  return caption;
}

// Send WhatsApp image message
async function sendWhatsAppImageMessage(toE164, imageUrl, caption) {
  if (!toE164) throw new Error('Missing recipient phone number (E.164 format)');
  if (!imageUrl) throw new Error('Missing image URL');

  const url = `https://graph.facebook.com/${WHATSAPP_API_VERSION}/${WHATSAPP_PHONE_NUMBER_ID}/messages`;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${WHATSAPP_TOKEN}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: toE164,
      type: 'image',
      image: {
        link: imageUrl,
        caption: caption || ''
      }
    })
  });

  const data = await resp.json();
  if (!resp.ok) {
    throw new Error(`WhatsApp send failed ${resp.status}: ${JSON.stringify(data)}`);
  }
  return data;
}

// Main processing function
async function processImageGeneration(jobData) {
  console.log('🚀 Starting image generation job...');
  console.log('Job data:', JSON.stringify({
    productCategory: jobData.productCategory,
    sceneDescription: jobData.sceneDescription,
    priceOverlay: jobData.priceOverlay,
    userPhone: jobData.userPhone,
    imageDataLength: jobData.actualImageData?.length || 0
  }, null, 2));

  try {
    // Generate the image
    const imageUrl = await generateImageFromAi(
      jobData.actualImageData,
      jobData.productCategory,
      jobData.sceneDescription,
      jobData.priceOverlay
    );
    
    console.log('✅ Image generation successful:', imageUrl);

    // Send to user if phone number is available
    if (jobData.userPhone) {
      const caption = createImageCaption(
        jobData.productCategory, 
        jobData.priceOverlay, 
        jobData.userPhone
      );
      
      console.log('📤 Sending WhatsApp image to:', jobData.userPhone);
      console.log('📝 Caption:', caption);
      
      try {
        const waResp = await sendWhatsAppImageMessage(jobData.userPhone, imageUrl, caption);
        console.log('✅ WhatsApp image sent successfully:', JSON.stringify(waResp));
      } catch (sendErr) {
        console.error('❌ Failed to send WhatsApp image:', sendErr);
      }
    } else {
      console.warn('⚠️ No phone number provided; image generated but not sent');
    }

    return {
      success: true,
      imageUrl,
      userPhone: jobData.userPhone,
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('❌ Image processing failed:', error);
    
    // Try to send error message to user if phone available
    if (jobData.userPhone) {
      try {
        await sendWhatsAppImageMessage(
          jobData.userPhone, 
          null, // No image
          `Sorry, there was an error processing your ${jobData.productCategory} image. Please try again later.`
        );
      } catch (sendErr) {
        console.error('❌ Failed to send error message:', sendErr);
      }
    }
    
    throw error;
  }
}

// --- Main Vercel API Handler ---
export default async function handler(req, res) {
  // Handle CORS
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

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  console.log('=== PROCESS JOB WEBHOOK ===');
  console.log('Body:', JSON.stringify({
    ...req.body,
    actualImageData: req.body.actualImageData ? `[${req.body.actualImageData.length} characters]` : 'missing'
  }, null, 2));

  try {
    const {
      actualImageData,
      productCategory,
      sceneDescription,
      priceOverlay,
      userPhone,
      decryptedBody
    } = req.body;

    // Validate required fields
    if (!actualImageData) {
      return res.status(400).json({
        success: false,
        error: 'Missing actualImageData'
      });
    }

    if (!productCategory) {
      return res.status(400).json({
        success: false,
        error: 'Missing productCategory'
      });
    }

    // Process the job
    const result = await processImageGeneration({
      actualImageData,
      productCategory,
      sceneDescription,
      priceOverlay,
      userPhone,
      decryptedBody
    });

    return res.status(200).json(result);

  } catch (error) {
    console.error('❌ Process job error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
}
