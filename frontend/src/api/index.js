import { apiFetch, apiFetchBlob } from './client';

export const authApi = {
  login: (email, password) => apiFetch('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password }),
  }),
};

export const systemApi = {
  getStatus: () => apiFetch('/api/v1/system/status'),
};

export const datasetApi = {
  getDatasets: () => apiFetch('/api/v1/datasets'),
  selectDataset: (datasetId) => apiFetch('/api/v1/datasets/select', {
    method: 'POST',
    body: JSON.stringify({ dataset_id: datasetId }),
  }),
};

export const forecastApi = {
  getHosts: () => apiFetch('/api/v1/forecast/hosts'),
  predict: (hostIp, horizon = 6) => apiFetch('/api/v1/forecast/predict', {
    method: 'POST',
    body: JSON.stringify({ host_ip: hostIp, horizon }),
  }),
  getWhatIfFeatures: () => apiFetch('/api/v1/forecast/what-if/features'),
  whatIf: (hostIp, feature, scale) => apiFetch('/api/v1/forecast/what-if', {
    method: 'POST',
    body: JSON.stringify({ host_ip: hostIp, feature, scale }),
  }),
};

export const responseApi = {
  simulateIsolation: (hostIp) => apiFetch('/api/v1/response/simulate-isolation', {
    method: 'POST',
    body: JSON.stringify({ host_ip: hostIp }),
  }),
};

export const explainApi = {
  getAttribution: (hostIp) => apiFetch('/api/v1/explainability/attribution', {
    method: 'POST',
    body: JSON.stringify({ host_ip: hostIp }),
  }),
  getNarrative: (hostIp) => apiFetch(`/api/v1/attacks/narrative?host_ip=${encodeURIComponent(hostIp)}`),
  getMitre: () => apiFetch('/api/v1/mitre/mapping'),
};

export const analysisApi = {
  uploadFile: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return apiFetch('/api/v1/analysis/upload', {
      method: 'POST',
      body: formData,
    });
  },
};

export const reportApi = {
  generateReport: (hostIp, format = 'json') => apiFetch('/api/v1/reports/generate', {
    method: 'POST',
    body: JSON.stringify({ host_ip: hostIp, format }),
  }),
  downloadReport: (filename) => apiFetch(`/api/v1/reports/download/${filename}`),
  downloadReportPdf: (hostIp) => apiFetchBlob(`/api/v1/reports/pdf/${encodeURIComponent(hostIp)}`),
};

export const evalApi = {
  getMetrics: () => apiFetch('/api/v1/eval/metrics'),
};
