import axios from 'axios';

export const generateMealPlan = async (req, res) => {
  try {
    // Get API key from environment at runtime
    const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
    const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';

    const { calories, dietType, allergies, goal } = req.body;

    // Validate input
    if (!calories) {
      return res.status(400).json({ error: 'Calories field is required' });
    }

    if (!GEMINI_API_KEY) {
      console.error('❌ GEMINI_API_KEY not configured in environment');
      console.error('Available env keys:', Object.keys(process.env).filter(k => k.includes('GEMINI')));
      return res.status(500).json({ error: 'API configuration error - GEMINI_API_KEY not set' });
    }

    console.log('✅ GEMINI_API_KEY found:', GEMINI_API_KEY.substring(0, 10) + '...');

    const promptText = `Buat rencana makan yang dipersonalisasi berdasarkan persyaratan berikut:
- Target kalori harian: ${calories} kalori
- Jenis diet: ${dietType || 'balanced'}
- Alergi/Pembatasan: ${allergies || 'Tidak ada'}
- Tujuan kebugaran: ${goal || 'maintenance'}

Buat rencana makan dengan 3 makanan (sarapan, makan siang, makan malam) yang memenuhi persyaratan ini.

PENTING: Respons HARUS berupa HANYA valid JSON, tanpa penjelasan tambahan atau markdown. Format:
{
  "breakfast": {
    "name":"nama makanan",
    "calories":500,
    "protein":30,
    "carbs":50,
    "fat":20,
    "ingredients":["bahan 1","bahan 2"],
    "instructions":"langkah demi langkah"
  },
  "lunch": {
    "name":"nama makanan",
    "calories":600,
    "protein":35,
    "carbs":60,
    "fat":25,
    "ingredients":["bahan 1","bahan 2"],
    "instructions":"langkah demi langkah"
  },
  "dinner": {
    "name":"nama makanan",
    "calories":500,
    "protein":30,
    "carbs":50,
    "fat":20,
    "ingredients":["bahan 1","bahan 2"],
    "instructions":"langkah demi langkah"
  }
}`;

    console.log('🍽️ Sending to Gemini API:', { calories, dietType, allergies, goal });

    const response = await axios.post(GEMINI_API_URL, {
      contents: [{
        parts: [{
          text: promptText
        }]
      }]
    }, {
      headers: {
        'Content-Type': 'application/json',
        'X-goog-api-key': GEMINI_API_KEY
      }
    });

    console.log('✅ Gemini API Response status:', response.status);

    if (!response.data.candidates?.[0]?.content?.parts?.[0]?.text) {
      console.error('Invalid response format:', response.data);
      return res.status(500).json({ error: 'Invalid API response format' });
    }

    const mealPlanText = response.data.candidates[0].content.parts[0].text;
    console.log('📝 Raw response text:', mealPlanText);

    // Parse JSON response
    let parsedPlan;
    try {
      // Try direct JSON parse
      parsedPlan = JSON.parse(mealPlanText);
    } catch (e) {
      // Try to extract JSON from text
      const jsonMatch = mealPlanText.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        console.error('Could not extract JSON from response:', mealPlanText);
        return res.status(500).json({ error: 'Could not parse meal plan from response' });
      }
      parsedPlan = JSON.parse(jsonMatch[0]);
    }

    console.log('🎯 Parsed meal plan:', parsedPlan);

    // Validate meal plan structure
    if (!parsedPlan.breakfast || !parsedPlan.lunch || !parsedPlan.dinner) {
      console.error('Invalid meal plan structure:', parsedPlan);
      return res.status(500).json({ error: 'Invalid meal plan structure from API' });
    }

    return res.status(200).json({
      success: true,
      data: parsedPlan
    });

  } catch (error) {
    console.error('❌ Error generating meal plan:', error.response?.data || error.message);
    
    if (error.response?.status === 404) {
      return res.status(404).json({ error: 'API endpoint not found. Check Gemini API configuration.' });
    }
    
    if (error.response?.status === 401 || error.response?.status === 403) {
      return res.status(401).json({ error: 'Invalid API key or access denied' });
    }

    return res.status(500).json({ 
      error: 'Failed to generate meal plan',
      message: error.message 
    });
  }
};
