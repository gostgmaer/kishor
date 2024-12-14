import requests from './httpServices';

const AttributeServices = {
  register: async () => {
    return requests.post('/authentication/user/register');
  },

  login: async () => {
    return requests.post(`/authentication/user/signin`);
  },

  logout: async (body) => {
    return requests.post('/authentication/user/signout', body);
  },

  confirm: async (body) => {
    return requests.post('/authentication/user/confirm/:token', body);
  },

  verify: async (id) => {
    return requests.post(`/authentication/user/verify/auth-token`);
  },

  refresh: async (id, body) => {
    return requests.post(`/authentication/user/token/refersh`, body);
  },

  reset: async (id, body) => {
    return requests.post(`/authentication/user/reset-password/:token`, body);
  },

  forget: async (id, body) => {
    return requests.post(`/authentication/user/forget-password`, body);
  },
  changes: async (id, body) => {
    return requests.post(`/authentication/user/change-password`, body);
  },
  profile: async (id, body) => {
    return requests.get(`/authentication/user/current/profile`, body);
  },
  update: async (id, body) => {
    return requests.patch(`/authentication/user/current/profile/update`, body);
  },
};

export default AttributeServices;
