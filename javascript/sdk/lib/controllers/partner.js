import Client from "../client";

/**
 * @class
 * @default
 * @param {Client} client
 */
export default class PartnerController {
  #client;

  /**
   * @param {Client} client
   */
  constructor(client) {
    this.#client = client;
  }

  /**
   * Attaches a partner to an account.
   *
   * @param {import("../types").AttachPartnerParams} params - The parameters for attaching a partner.
   * @param {import("../types").ControlCode} params.partnerCode - The partner code, with options: INVALID (0), CROWDSTRIKE (1), DEFENDER (2), SPLUNK (3).
   * @param {string} params.api - The API endpoint for the partner.
   * @param {string} params.user - The user associated with the partner.
   * @param {string} [params.secret=""] - The secret key (optional, default is an empty string).
   * @param {import("../types").RequestOptions} [options={}] - Additional request options (optional).
   * @returns {Promise<string>} A promise that resolves to the response text from the request.
   */
  async attachPartner(params, options = {}) {
    const { partnerCode, api, user, secret = "" } = params;

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

  /**
   * Detaches a partner from an account
   *
   * @param {import("../types").ControlCode} partnerCode - The partner code, with options: INVALID (0), CROWDSTRIKE (1), DEFENDER (2), SPLUNK (3).
   * @param {import("../types").RequestOptions} [options={}] - Optional request options.
   * @returns {Promise<string>} A Promise that resolves to the response text.
   */
  async detachPartner(partnerCode, options = {}) {
    const response = await this.#client.requestWithAuth(
      `/partner/${partnerCode}`,
      {
        method: "DELETE",
        ...options,
      }
    );

    return response.text();
  }

  /**
   * Get a list of endpoints from all partners.
   *
   * @param {import("../types").EndpointsParams} params - The parameters for fetching endpoints.
   * @param {import("../types").ControlCode} params.partnerCode - The partner code, with options: INVALID (0), CROWDSTRIKE (1), DEFENDER (2), SPLUNK (3).
   * @param {string} params.platform - The platform.
   * @param {string} [params.hostname=""] - The hostname (optional, default is empty string).
   * @param {number} [params.offset=0] - The offset (optional, default is 0).
   * @param {number} [params.count=100] - The count returned (optional, default is 100).
   * @param {import("../types").RequestOptions} [options={}] - Optional request options.
   * @returns {Promise<import("../types").PartnerEndpoints>} A promise that resolves to the list of endpoints from partners.
   */
  async endpoints(params, options = {}) {
    const {
      partnerCode,
      platform,
      hostname = "",
      offset = 0,
      count = 100,
    } = params;

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

  /**
   * Deploy probes on all specified partner endpoints.
   *
   * @param {import("../types").DeployParams} params - The parameters for deploying probes.
   * @param {import("../types").ControlCode} params.partnerCode - The partner code, with options: INVALID (0), CROWDSTRIKE (1), DEFENDER (2), SPLUNK (3).
   * @param {string[]} params.hostIds - An array of host IDs to deploy probes on.
   * @param {import("../types").RequestOptions} [options={}] - Optional request options.
   * @returns {Promise<void>} A promise that resolves when the deployment is complete.
   */
  async deploy(params, options = {}) {
    const { partnerCode, hostIds } = params;

    await this.#client.requestWithAuth(`/partner/deploy/${partnerCode}`, {
      method: "POST",
      body: JSON.stringify({ host_ids: hostIds }),
      ...options,
    });
  }
}
