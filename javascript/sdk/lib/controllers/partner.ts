import Client from "../client";
import {
  AttachPartnerParams,
  ControlCode,
  DeployParams,
  EndpointsParams,
  PartnerEndpoints,
  RequestOptions,
} from "../types";

export default class PartnerController {
  #client: Client;

  constructor(client: Client) {
    this.#client = client;
  }

  async attachPartner(
    { partnerCode, api, user, secret = "" }: AttachPartnerParams,
    options: RequestOptions = {}
  ) {
    const response = await this.#client.requestWithAuth(
      `/partner/${partnerCode}`,
      {
        method: "POST",
        body: JSON.stringify({ api, user, secret }),
        ...options,
      }
    );

    return response.text();
  }

  async detachPartner(partnerCode: ControlCode, options: RequestOptions = {}) {
    const response = await this.#client.requestWithAuth(
      `/partner/${partnerCode}`,
      {
        method: "DELETE",
        ...options,
      }
    );

    return response.text();
  }

  /** Get a list of endpoints from all partners */
  async endpoints(
    {
      partnerCode,
      platform,
      hostname = "",
      offset = 0,
      count = 100,
    }: EndpointsParams,
    options: RequestOptions = {}
  ): Promise<PartnerEndpoints> {
    const searchParams = new URLSearchParams({
      platform,
      hostname,
      offset: offset.toString(),
      count: count.toString(),
    });

    const response = await this.#client.requestWithAuth(
      `/partner/endpoints/${partnerCode}?${searchParams.toString()}`,
      {
        method: "GET",
        ...options,
      }
    );

    return response.json();
  }

  /** Deploy probes on all specified partner endpoints */
  async deploy(
    { partnerCode, hostIds }: DeployParams,
    options: RequestOptions = {}
  ): Promise<void> {
    await this.#client.requestWithAuth(`/partner/deploy/${partnerCode}`, {
      method: "POST",
      body: JSON.stringify({ host_ids: hostIds }),
      ...options,
    });
  }
}
