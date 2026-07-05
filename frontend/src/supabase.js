import { createClient } from '@supabase/supabase-js';

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL;
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY;

export const supabase = createClient(supabaseUrl, supabaseAnonKey, {
  auth: {
    persistSession: false,  // 🔒 Evita que Supabase intente guardar sesiones por su cuenta
    autoRefreshToken: false // Desactiva refrescos automáticos que consuman recursos innecesarios
  }
});