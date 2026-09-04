import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || 'https://tyunqthoinamdlyhgmuq.supabase.co';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || import.meta.env.VITE_SUPABASE_KEY || 'placeholder-key';

if (!import.meta.env.VITE_SUPABASE_URL) {
  console.warn('⚠️ VITE_SUPABASE_URL no detectada, usando fallback.');
}

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: { persistSession: true, autoRefreshToken: true },
});