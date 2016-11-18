/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.wso2.carbon.clustering.azure;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.hazelcast.config.Config;
import com.hazelcast.config.NetworkConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.Member;
import com.hazelcast.core.MemberAttributeEvent;
import com.hazelcast.core.MembershipEvent;
import com.hazelcast.core.MembershipListener;
import com.microsoft.aad.adal4j.AuthenticationResult;
import org.apache.axis2.clustering.ClusteringFault;
import org.apache.axis2.clustering.ClusteringMessage;
import org.apache.axis2.description.Parameter;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.clustering.azure.authentication.Authentication;
import org.wso2.carbon.clustering.azure.domain.IPConfiguration;
import org.wso2.carbon.clustering.azure.domain.NetworkInterface;
import org.wso2.carbon.clustering.azure.domain.NetworkSecurityGroup;
import org.wso2.carbon.clustering.azure.domain.VirtualMachine;
import org.wso2.carbon.clustering.azure.domain.VirtualMachines;
import org.wso2.carbon.clustering.azure.exceptions.AzureMembershipSchemeException;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastCarbonClusterImpl;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastMembershipScheme;
import org.wso2.carbon.core.clustering.hazelcast.HazelcastUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Azure membership scheme provides carbon cluster discovery on Microsoft Azure
 */
public class AzureMembershipScheme implements HazelcastMembershipScheme {

    private static final Log log = LogFactory.getLog(AzureMembershipScheme.class);
    private final NetworkConfig nwConfig;
    private final Map<String, Parameter> parameters;
    private final List<ClusteringMessage> messageBuffer;
    private HazelcastInstance primaryHazelcastInstance;
    private HazelcastCarbonClusterImpl carbonCluster;

    public AzureMembershipScheme(Map<String, Parameter> parameters, String primaryDomain, Config config,
            HazelcastInstance primaryHazelcastInstance, List<ClusteringMessage> messageBuffer) {
        this.parameters = parameters;
        this.primaryHazelcastInstance = primaryHazelcastInstance;
        this.messageBuffer = messageBuffer;
        this.nwConfig = config.getNetworkConfig();
    }

    @Override public void setPrimaryHazelcastInstance(HazelcastInstance primaryHazelcastInstance) {
        this.primaryHazelcastInstance = primaryHazelcastInstance;
    }

    @Override public void setLocalMember(Member localMember) {
    }

    @Override public void setCarbonCluster(HazelcastCarbonClusterImpl hazelcastCarbonCluster) {
        this.carbonCluster = hazelcastCarbonCluster;
    }

    @Override public void init() throws ClusteringFault {
        try {
            log.info("Initializing Azure membership scheme...");
            nwConfig.getJoin().getMulticastConfig().setEnabled(false);
            nwConfig.getJoin().getAwsConfig().setEnabled(false);
            TcpIpConfig tcpIpConfig = nwConfig.getJoin().getTcpIpConfig();
            tcpIpConfig.setEnabled(true);

            String azureAPIVersion = getConstant(AzureConstants.AZURE_API_VERSION,
                    AzureConstants.DEFAULT_AZURE_API_VERSION, true);
            String ARMEndPoint = getConstant(AzureConstants.ARM_ENDPOINT, AzureConstants.DEFAULT_ARM_ENDPOINT, true);
            String authorizationEndPoint = getConstant(AzureConstants.AUTHORIZATION_ENDPOINT,
                    AzureConstants.DEFAULT_AUTHORIZATION_ENDPOINT, true);
            String username = getConstant(AzureConstants.AZURE_USERNAME, "", true);
            String credential = getConstant(AzureConstants.AZURE_CREDENTIAL, "", false);
            String tenantId = getConstant(AzureConstants.AZURE_TENANT_ID, "", false);
            String clientId = getConstant(AzureConstants.AZURE_CLIENT_ID, "", false);
            String subscriptionId = getConstant(AzureConstants.AZURE_SUBSCRIPTION_ID, "", false);
            String resourceGroup = getConstant(AzureConstants.AZURE_RESOURCE_GROUP, "", false);
            String networkSecurityGroup = getConstant(AzureConstants.AZURE_NETWORK_SECURITY_GROUP, "", true);
            String networkInterfaceTagKey = getConstant(AzureConstants.AZURE_NETWORK_INTERFACE_TAG_KEY, "", true);
            String networkInterfaceTagValue = getConstant(AzureConstants.AZURE_NETWORK_INTERFACE_TAG_VALUE, "", true);
            String virtualMachineScaleSets = getConstant(AzureConstants.AZURE_VIRTUAL_MACHINE_SCALE_SETS, "", true);
            boolean validateAuthority = Boolean
                    .parseBoolean(getConstant(AzureConstants.AZURE_VALIDATE_AUTHORITY, "false", true));

            if (networkSecurityGroup == null && virtualMachineScaleSets == null) {
                throw new ClusteringFault(String.format("Both %s and %s params are empty. Define at least one of them",
                        AzureConstants.AZURE_NETWORK_SECURITY_GROUP, AzureConstants.AZURE_VIRTUAL_MACHINE_SCALE_SETS));
            }

            log.info(String.format("Azure clustering configuration: [authorization-endpoint] %s , [arm-endpoint] %s , "
                    + "[tenant-id] %s , [client-id] %s", authorizationEndPoint, ARMEndPoint, tenantId, clientId));

            AuthenticationResult authResult = Authentication
                    .getAuthToken(authorizationEndPoint, username, credential, tenantId, clientId, validateAuthority,
                            ARMEndPoint);

            if (authResult != null && StringUtils.isNotEmpty(authResult.getAccessToken())) {
                List<String> ipAddresses = findIPAddresses(ARMEndPoint, azureAPIVersion, authResult.getAccessToken(),
                        subscriptionId, resourceGroup, networkSecurityGroup, networkInterfaceTagKey,
                        networkInterfaceTagValue, virtualMachineScaleSets);
                for (Object IPAddress : ipAddresses) {
                    nwConfig.getJoin().getTcpIpConfig().addMember(IPAddress.toString());
                    log.info(String.format("Member added to cluster configuration: [ip-address] %s",
                            IPAddress.toString()));
                }
            }

            log.info("Azure membership scheme initialized successfully");
        } catch (Exception ex) {
            throw new ClusteringFault("Azure membership initialization failed", ex);
        }
    }

    private List<String> findIPAddresses(String ARMEndPoint, String azureAPIVersion, String accessToken,
            String subscriptionID, String resourceGroup, String networkSecurityGroup, String networkInterfaceTagKey,
            String networkInterfaceTagValue, String virtualMachineScaleSets) throws AzureMembershipSchemeException {

        List<String> ipAddresses = new ArrayList<>();
        Gson gson = new GsonBuilder().create();

        if ((StringUtils.isNotEmpty(networkSecurityGroup)) && (StringUtils.isEmpty(virtualMachineScaleSets))) {

            // Find IP addresses based on network security group

            String url = ARMEndPoint + String
                    .format(AzureConstants.NETWORK_SECURITY_GROUPS_RESOURCE, subscriptionID, resourceGroup,
                            networkSecurityGroup) + "?" + AzureConstants.API_VERSION_QUERY_PARAM + azureAPIVersion;
            try {

                // Get network security group
                NetworkSecurityGroup nsg = gson
                        .fromJson(inputStreamToString(invokeGetMethod(url, accessToken)), NetworkSecurityGroup.class);

                //Get network security group's network interface names
                if (nsg.getProperties().getNetworkInterfaces() == null) {
                    log.warn(String.format("Could not find VMs belongs to [network-security-group] %s",
                            networkSecurityGroup));
                } else {
                    boolean hasTag = false;
                    for (String networkInterfaceName : nsg.getProperties().getNetworkInterfaceNames()) {
                        // Get network interface by network interface name
                        url = ARMEndPoint + String
                                .format(AzureConstants.NETWORK_INTERFACES_RESOURCE, subscriptionID, resourceGroup,
                                        networkInterfaceName) + "?" + AzureConstants.API_VERSION_QUERY_PARAM
                                + azureAPIVersion;
                        NetworkInterface networkInterface = gson
                                .fromJson(inputStreamToString(invokeGetMethod(url, accessToken)),
                                        NetworkInterface.class);

                        // Filter the network interfaces belongs to the networkInterfaceTag
                        if ((StringUtils.isNotEmpty(networkInterfaceTagKey)) && (StringUtils
                                .isNotEmpty(networkInterfaceTagValue)) && (!networkInterfaceTagValue
                                .equals(networkInterface.getTags().get(networkInterfaceTagKey)))) {

                            // NetworkInterface doesn't have the specified network interface tag value
                            continue;
                        }
                        hasTag= true;

                        // Get the IP addresses of network interfaces which has specified tag if provided
                        if ((networkInterface.getProperties().getIpConfigurations() == null)) {
                            log.warn(String.format(
                                    "Could not find IP addresses of VMs belongs to [network-security-group] %s",
                                    networkSecurityGroup));
                        } else {
                            for (IPConfiguration ipConfig : networkInterface.getProperties().getIpConfigurations()) {
                                ipAddresses.add(ipConfig.getIpConfigurationProperties().getPrivateIPAddress());
                            }
                        }
                    }
                    if ((StringUtils.isNotEmpty(networkInterfaceTagKey)) && (StringUtils
                            .isNotEmpty(networkInterfaceTagValue)) && !(hasTag)){
                        log.warn(String.format(
                                "Could not find VMs belongs to [network-security-group] %s "
                                        + "[network-interface-tag-key] %s and [network-interface-tag-value] %s",
                                networkSecurityGroup, networkInterfaceTagKey, networkInterfaceTagValue));
                    }
                }
            } catch (IOException ex) {
                throw new AzureMembershipSchemeException("Could not find VM IP addresses", ex);
            }
        } else if ((StringUtils.isNotEmpty(virtualMachineScaleSets)) && (StringUtils.isEmpty(networkSecurityGroup))) {

            // Get list of vmss provided
            String [] vmss = virtualMachineScaleSets.split(",");

            // Find members' IP addresses based on virtual machine scale set
            try {
                for(String virtualMachineScaleSet : vmss) {
                    // Get virtual machines belongs to a specific virtualMachineScaleSet
                    String url = ARMEndPoint + String
                            .format(AzureConstants.VIRTUAL_MACHINE_SCALE_SET_VIRTUAL_MACHINES_RESOURCE, subscriptionID,
                                    resourceGroup, virtualMachineScaleSet) + "?" + AzureConstants.API_VERSION_QUERY_PARAM
                            + azureAPIVersion;
                    VirtualMachines virtualMachines = gson
                            .fromJson(inputStreamToString(invokeGetMethod(url, accessToken)), VirtualMachines.class);

                    // Get network interfaces' IP address
                    for (VirtualMachine virtualMachine : virtualMachines.getValue()) {
                        if (virtualMachine.getProperties().getNetworkProfile() == null) {
                            log.warn(String.format("Could not find VMs belongs to [virtual-machine-scale-set] %s",
                                    virtualMachineScaleSet));
                        } else {
                            for (String networkInterfaceName : virtualMachine.getProperties().getNetworkProfile().getNetworkInterfaceNames()) {
                                url = ARMEndPoint + String.format(AzureConstants.VIRTUAL_MACHINE_SCALE_SET_NETWORK_INTERFACES_RESOURCE,
                                        subscriptionID, resourceGroup, virtualMachineScaleSet, virtualMachine.getInstanceId(), networkInterfaceName) + "?"
                                        + AzureConstants.API_VERSION_QUERY_PARAM + azureAPIVersion;
                                NetworkInterface networkInterface = gson
                                        .fromJson(inputStreamToString(invokeGetMethod(url, accessToken)),
                                                NetworkInterface.class);
                                if (networkInterface.getProperties().getIpConfigurations() == null) {
                                    log.warn(String.format(
                                            "Could not find IP addresses of VMs belongs to [virtual-machine-scale-set] %s",
                                            virtualMachineScaleSet));
                                } else {
                                    for (IPConfiguration ipConfig : networkInterface.getProperties().getIpConfigurations()) {
                                        ipAddresses.add(ipConfig.getIpConfigurationProperties().getPrivateIPAddress());
                                    }
                                }
                            }
                        }
                    }
                }

            } catch (IOException ex) {
                throw new AzureMembershipSchemeException("Could not find VM IP addresses", ex);
            }
        } else {
            throw new AzureMembershipSchemeException(
                    "The networkSecurityGroup or virtualMachineScaleSet must be chosen as the grouping method");
        }
        return ipAddresses;
    }

    private InputStream invokeGetMethod(String url, String accessToken) throws AzureMembershipSchemeException {

        InputStream inputStream;
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
            connection.setRequestProperty(AzureConstants.AUTHORIZATION_HEADER, "Bearer " + accessToken);
            inputStream = connection.getInputStream();
        } catch (IOException ex) {
            throw new AzureMembershipSchemeException("Could not connect to Azure API", ex);
        }
        return inputStream;
    }

    public void joinGroup() throws ClusteringFault {
        primaryHazelcastInstance.getCluster().addMembershipListener(new AzureMembershipSchemeListener());
    }

    private Parameter getParameter(String name) {
        return parameters.get(name);
    }

    private String getConstant(String constant, String defaultValue, boolean isOptional) throws ClusteringFault {
        String param = System.getenv(constant);
        Parameter parameter;
        if (StringUtils.isEmpty(param)) {
            parameter = getParameter(constant);
            if (parameter == null) {
                param = defaultValue;
                if (StringUtils.isEmpty(param) && !isOptional) {
                    //should leave default value blank if the value is mandatory
                    throw new ClusteringFault(String.format("Azure %s parameter not found", constant));
                } else if (StringUtils.isEmpty(param)) {
                    param = null;
                }
            } else {
                return parameter.getValue().toString();
            }
        }
        return param;
    }

    private String inputStreamToString(InputStream inStream) throws IOException {
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(inStream), 1000);
        for (String line = r.readLine(); line != null; line = r.readLine()) {
            sb.append(line);
        }
        inStream.close();
        return sb.toString();
    }

    private class AzureMembershipSchemeListener implements MembershipListener {

        @Override public void memberAdded(MembershipEvent membershipEvent) {
            Member member = membershipEvent.getMember();
            // Send all cluster messages
            carbonCluster.memberAdded(member);
            log.info(String.format("Member joined [uuid] %s [address] %s", member.getUuid(),
                    member.getSocketAddress().toString()));
            // Wait for sometime for the member to completely join before replaying messages
            try {
                Thread.sleep(5000);
            } catch (InterruptedException ignored) {
            }
            HazelcastUtil.sendMessagesToMember(messageBuffer, member, carbonCluster);
        }

        @Override public void memberRemoved(MembershipEvent membershipEvent) {
            Member member = membershipEvent.getMember();
            carbonCluster.memberRemoved(member);
            log.info(String.format("Member left [uuid] %s [address] %s", member.getUuid(),
                    member.getSocketAddress().toString()));
        }

        @Override public void memberAttributeChanged(MemberAttributeEvent memberAttributeEvent) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Member attribute changed [%s] %s", memberAttributeEvent.getKey(),
                        memberAttributeEvent.getValue()));
            }
        }
    }
}
