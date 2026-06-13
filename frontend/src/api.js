import axios from "axios";

const API = axios.create({ baseURL: "/api" });

export const scanFiles = (files, onUploadProgress) => {
  const form = new FormData();
  Array.from(files).forEach((f) => form.append("files", f));
  return API.post("/scan", form, {
    headers: { "Content-Type": "multipart/form-data" },
    onUploadProgress,
  });
};

export const getScanResult  = (id)  => API.get(`/scan/${id}`);
export const deleteScan     = (id)  => API.delete(`/scan/${id}`);
export const getHistory     = ()    => API.get("/history");
export const quarantineFile = (id)  => API.post("/quarantine", { scan_id: id });
export const getEngineStatus = ()   => API.get("/status");
