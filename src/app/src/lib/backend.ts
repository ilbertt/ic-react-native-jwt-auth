import { HOST_IP } from "./common";

export type ApiResponse = {
  status: number;
  data?: {
    principal: string;
    user_id: string;
  };
};

export const fetchApi = async (jwt?: string): Promise<ApiResponse> => {
  const response = await fetch(`http://${HOST_IP}:3000/authenticated`, {
    headers: jwt ? {
      Authorization: `Bearer ${jwt}`,
    } : {},
  });

  if (response.status !== 200) {
    return { status: response.status };
  }

  const data = await response.json();
  return { status: response.status, data };
};
