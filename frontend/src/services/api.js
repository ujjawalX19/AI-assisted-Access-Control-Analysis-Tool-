import axios from 'axios';

const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL || 'http://localhost:8000',
  timeout: 30000,
});

// Inject JWT token from localStorage on every request
API.interceptors.request.use((config) => {
  const token = localStorage.getItem('bac_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// Auto-redirect on 401
API.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('bac_token');
      localStorage.removeItem('bac_user');
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ---- Auth ----
export const authAPI = {
  register: (data) => API.post('/api/auth/register', data),
  login: (data) => API.post('/api/auth/login', data),
  me: () => API.get('/api/auth/me'),
};

// ---- Projects ----
export const projectsAPI = {
  list: () => API.get('/api/projects'),
  create: (data) => API.post('/api/projects', data),
  get: (id) => API.get(`/api/projects/${id}`),
  delete: (id) => API.delete(`/api/projects/${id}`),
};

// ---- API Requests ----
export const requestsAPI = {
  create: (data) => API.post('/api/requests', data),
  listByProject: (projectId) => API.get(`/api/requests/project/${projectId}`),
};

// ---- Scans ----
export const scansAPI = {
  start: (data) => API.post('/api/scans/start', data),
  status: (scanId) => API.get(`/api/scans/${scanId}/status`),
  results: (scanId) => API.get(`/api/scans/${scanId}/results`),
  graph: (scanId) => API.get(`/api/scans/${scanId}/graph`),
  listByProject: (projectId) => API.get(`/api/scans/project/${projectId}`),
};

// ---- Demo Target ----
export const demoAPI = {
  tokens: () => axios.get('http://localhost:8001/api/auth/tokens'),
};

export default API;
