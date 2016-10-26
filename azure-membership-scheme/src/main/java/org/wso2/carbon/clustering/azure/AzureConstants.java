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

/**
 * AzureConstants for Azure membership scheme
 */
public class AzureConstants {

    public final static String AUTHORIZATION_ENDPOINT = "https://login.microsoftonline.com";
    public final static String ARM_ENDPOINT = "https://management.azure.com";

    public final static String NETWORK_SECURITY_GROUPS_RESOURCE = "/subscriptions/%s/resourceGroups/%s/providers/"
            + "Microsoft.Network/networkSecurityGroups/%s?api-version=2016-03-30";
    public final static String NETWORK_INTERFACES_RESOURCE = "/subscriptions/%s/resourceGroups/%s/providers/"
            + "Microsoft.Network/networkInterfaces/%s?api-version=2016-03-30";
    public final static String TAGS_RESOURCE = "/subscriptions/%s/resources?$filter=tagname+eq+'%s'&api-version=2015-01-01";
    public final static String VIRTUAL_MACHINE_SCALE_SET_VIRTUAL_MACHINES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
                    + ".Compute/virtualMachineScaleSets/%s/virtualMachines?api-version=2016-03-30";
    public final static String VIRTUAL_MACHINE_SCALE_SET_NETWORK_INTERFACES_RESOURCE =
            "/subscriptions/%s/resourceGroups/%s/providers/Microsoft"
                    + ".Compute/virtualMachineScaleSets/%s/virtualMachines/%s/networkInterfaces/%s?api-version=2016-03-30";

    public final static String AZURE_USERNAME = "azure_username";
    public final static String CREDENTIAL = "credential";
    public final static String TENANT_ID = "tenantId";
    public final static String CLIENT_ID = "clientId";
    public final static String SUBSCRIPTION_ID = "subscriptionId";
    public final static String RESOURCE_GROUP = "resourceGroup";
    public final static String NETWORK_SECURITY_GROUP = "networkSecurityGroup";
    public final static String NETWORK_INTERFACE_TAG = "networkInterfaceTag";
    public final static String VIRTUAL_MACHINE_SCALE_SET = "virtualMachineScaleSet";
    public final static String VALIDATION_AUTHORITY = "validationAuthority";
}
