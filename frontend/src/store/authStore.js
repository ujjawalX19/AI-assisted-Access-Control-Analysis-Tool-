import { create } from 'zustand';
import { authAPI } from '../services/api';

const useAuthStore = create((set) => ({
  user: JSON.parse(localStorage.getItem('bac_user') || 'null'),
  token: localStorage.getItem('bac_token') || null,
  isLoading: false,
  error: null,

  login: async (email, password) => {
    set({ isLoading: true, error: null });
    try {
      const res = await authAPI.login({ email, password });
      const { access_token, user_id, email: userEmail, role } = res.data;
      const user = { id: user_id, email: userEmail, role };
      localStorage.setItem('bac_token', access_token);
      localStorage.setItem('bac_user', JSON.stringify(user));
      set({ user, token: access_token, isLoading: false });
      return { success: true };
    } catch (err) {
      const msg = err.response?.data?.detail || 'Login failed';
      set({ error: msg, isLoading: false });
      return { success: false, error: msg };
    }
  },

  register: async (email, password, full_name) => {
    set({ isLoading: true, error: null });
    try {
      await authAPI.register({ email, password, full_name });
      set({ isLoading: false });
      return { success: true };
    } catch (err) {
      const msg = err.response?.data?.detail || 'Registration failed';
      set({ error: msg, isLoading: false });
      return { success: false, error: msg };
    }
  },

  logout: () => {
    localStorage.removeItem('bac_token');
    localStorage.removeItem('bac_user');
    set({ user: null, token: null });
  },

  clearError: () => set({ error: null }),
}));

export default useAuthStore;
