# Azure Membership Scheme

Azure membership scheme provides features for automatically discovering WSO2 Carbon server clusters on Azure.

##How It Works

Once a Carbon server starts it will query Virtual Machine IP addresses in the given cluster via Azure API. Before the cluster starts, it should be ensured that either all of the virtual machines in the cluster are added to a particular network security group or the virtual machines are created using Azure Virtual Machine Scale Set. Additionally if the VMs are grouped by the network security group, the network interfaces can be tagged as needed and VMs belongs to a network security group can be further filtered by network interface tag name. Thereafter Hazelcast network configuration will be updated with the above VM IP addresses. As a result the Hazelcast instance will get connected to all the other members in the cluster. In addition once a new member is added to the cluster, all the other members will get connected to the new member.

##Installation

1. For Azure Membership Scheme to work, Hazelcast configuration should be made pluggable. This has to be enabled in the WSO2 products in different ways. For WSO2 products that are based on Carbon 4.2.0, [apply kernel patch0012](https://docs.wso2.com/display/Carbon420/Applying+a+Patch+to+the+Kernel). For Carbon 4.4.1 based products apply [patch0005](http://product-dist.wso2.com/downloads/carbon/4.4.1/patch0005/WSO2-CARBON-PATCH-4.4.1-0005.zip). These patches include a modification in the Carbon Core component for allowing to add third party membership schemes. WSO2 products that are based on Carbon versions later than 4.4.1 do not need any patches to be applied (To determine the Carbon version of a particular product, please refer to the [WSO2 Release Matrix](http://wso2.com/products/carbon/release-matrix/)).

2. Copy following JAR files to the repository/components/lib directory of the Carbon server:

adal4j-0.0.2.jar
azure-membership-scheme-1.0-SNAPSHOT.jar
commons-lang3-3.3.1.jar
commons-logging-1.2.jar
oauth2-oidc-sdk-4.5.jar

3. Update axis2.xml with the following configuration:
 
```xml
<clustering class="org.wso2.carbon.core.clustering.hazelcast.HazelcastClusteringAgent" enable="true">
    
    <parameter name="membershipSchemeClassName">org.wso2.carbon.clustering.azure.AzureMembershipScheme</parameter>
    <parameter name="membershipScheme">azure</parameter>
    <parameter name="AZURE_SUBSCRIPTION_ID">Azure Subscription ID</parameter>
    <parameter name="AZURE_TENANT_ID">Azure Active Directory Tenant ID</parameter>
    <parameter name="AZURE_CLIENT_ID">Azure AD Application Client ID</parameter>
    <parameter name="AZURE_CREDENTIAL">Azure AD Application Client Secret</parameter>
    <parameter name="AZURE_RESOURCE_GROUP">Azure Resource Group in which your cluster is deployed</parameter>
    <parameter name="AZURE_NETWORK_SECURITY_GROUP">Azure Network Security Group of cluster VMs</parameter>
    <parameter name="AZURE_NETWORK_INTERFACE_TAG">Azure Network Interface Tag name of the VMs in the cluster</parameter>
    <parameter name="AZURE_VIRTUAL_MACHINE_SCALE_SET">Azure Virtual Machine Scale Set name to which the cluster VMs belongs to</parameter>
  
</clustering> 
```
  
###Clustering Parameters

* In order to use Azure membership scheme to cluster carbon servers(VMs) in Azure PaaS, set the membershipScheme to 'azure' and the membershipSchemeClassName to org.wso2.carbon.clustering.azure.AzureMembershipScheme' as shown above.

* Following parameters are needed to access Azure resource details.
    1. AZURE_SUBSCRIPTION_ID - Azure Subscription ID
    2. AZURE_TENANT_ID - Azure Active Directory(AD) Tenant ID
    3. AZURE_CLIENT_ID - Azure AD Application Client ID
    4. AZURE_CREDENTIAL - Azure AD Application Client Secret
    5. AZURE_USERNAME - Azure User Name (optional)
    6. AZURE_VALIDATE_AUTHORITY - Enable/disable authority address validation (optional) and default value is set to false
   
   The Azure by default uses 'https://login.microsoftonline.com/' as authorization endpoint and 'https://management.azure.com/' as Azure Resource Manager(ARM) endpoint. If this endpoint values are different from these default values, set them using 'AUTHORIZATION_ENDPOINT' and 'ARM_ENDPOINT' parameters.
      
   The Azure membership scheme uses '2016-03-30' as default Azure API version. Azure API version can be configured using 'AZURE_API_VERSION' parameter.
   

* All carbon servers (VMs) which has to be added to the same cluster has to created under same Azure Resource Group. The carbon servers which has to be clustered can be grouped by Azure Network Security Group(NSG) or Azure Virtual Machine Scale Set(VMSS) when VMs are created.
It has to be ensured NSG has only VMs which are needed to be added to the same cluster and there is a one to one mapping between NSG's network interfaces and VMs. If needed we can further group VMs which belongs to a NSG by creating tags for NSG Network Interfaces and can filter only required VMs by Network Interface tag.
The VMSS based clustering can be used when auto scaling feature is needed. We can create VMs which belongs to the same cluster using a VMSS with required scale rules. Following are Azure PaaS related params used to cluster carbon servers. Either NSG or VMSS based clustering can be used but not both.
    1. AZURE_RESOURCE_GROUP - Azure Resource Group name where the cluster is deployed
    2. AZURE_NETWORK_SECURITY_GROUP - Azure Network Security Group where relevant VMs are added to
    3. AZURE_NETWORK_INTERFACE_TAG_KEY - Azure Tag name of the NSG's Network Interface (optional)
    4. AZURE_NETWORK_INTERFACE_TAG_VALUE - Azure Tag value of the NSG's Network Interface (optional)
    5. AZURE_VIRTUAL_MACHINE_SCALE_SET - Azure Virtual Machine Scale Set name to which the cluster VMs belongs to


####Sample clustering configuration
  
#####Configuration 1: Clustering VMs using Azure Network Security Group 

######Configuration 1.1: Azure Network Security Group based clustering with Network Interface Tag

```xml
<clustering class="org.wso2.carbon.core.clustering.hazelcast.HazelcastClusteringAgent" enable="true">

    <parameter name="membershipSchemeClassName">com.osura.membershipscheme.azure.AzureMembershipScheme</parameter>
    <parameter name="membershipScheme">azure</parameter>
    <parameter name="AZURE_SUBSCRIPTION_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_TENANT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CLIENT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CREDENTIAL">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_RESOURCE_GROUP">wso2esbrg</parameter>
    <parameter name="AZURE_NETWORK_SECURITY_GROUP">wso2esbnwsg</parameter>
    <parameter name="AZURE_NETWORK_INTERFACE_TAG_KEY">esb-ni</parameter>
    <parameter name="AZURE_NETWORK_INTERFACE_TAG_VALUE">esb500</parameter>
 
</clustering>
```

######Configuration 1.2: Azure Network Security Group based clustering without Network Interface Tag
  
```xml
<clustering class="org.wso2.carbon.core.clustering.hazelcast.HazelcastClusteringAgent" enable="true">

    <parameter name="membershipSchemeClassName">com.osura.membershipscheme.azure.AzureMembershipScheme</parameter>
    <parameter name="membershipScheme">azure</parameter>
    <parameter name="AZURE_SUBSCRIPTION_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_TENANT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CLIENT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CREDENTIAL">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_RESOURCE_GROUP">wso2esbrg</parameter>
    <parameter name="AZURE_NETWORK_SECURITY_GROUP">wso2esbnwsg</parameter>

</clustering>
```

  
#####Configuration 3: Clustering VMs using Azure Virtual Machine Scale Set
  
```xml
<clustering class="org.wso2.carbon.core.clustering.hazelcast.HazelcastClusteringAgent" enable="true">
 
    <parameter name="membershipSchemeClassName">com.osura.membershipscheme.azure.AzureMembershipScheme</parameter>
    <parameter name="membershipScheme">azure</parameter>
    <parameter name="AZURE_SUBSCRIPTION_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_TENANT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CLIENT_ID">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_CREDENTIAL">xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx</parameter>
    <parameter name="AZURE_RESOURCE_GROUP">wso2esbrg</parameter>
    <parameter name="AZURE_VIRTUAL_MACHINE_SCALE_SET">esbvmss</parameter>
 
</clustering>
```
