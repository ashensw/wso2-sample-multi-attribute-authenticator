## WSO2 Identity Server Multi attribute authenticator - Sample

This is a sample authnticator which will allow users to login using username or mobile number as username.

This sample is compatible with WSO2 IS 5.10.0 or later.

### Steps to deploy
- Build the component by running "mvn clean install"
- Copy the `wso2-sample-multi-attribute-authenticator-1.0.jar` file which can be found in `target` directory into `<IS_HOME>/repository/components/dropins/` directory.
- Copy the `login.jsp` file which can be found in `src/main/resources` directory into `<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/` directory.
- Copy the `Resources.properties` file which can be found in `src/main/resources` directory into `<IS_HOME>/repository/deployment/server/webapps/authenticationendpoint/WEB-INF/classes/org/wso2/carbon/identity/application/authentication/endpoint/i18n/` directory.
- Resatrt the WSO2 IS 5.10.0 server.
  
### How to configure
- Select the custom-multi-attribute-authenticator as the `Local Authentication` in the `Local & Outbound Authentication Configuration` for your service provider.


<img src="https://github.com/ashensw/wso2-sample-multi-attribute-authenticator/blob/master/src/main/resources/how-to-configure.gif" width="75%" title="how-to-configure"> 


### How to try
- Try login using your mobile no or username as for your preference. 

<img src="https://github.com/ashensw/wso2-sample-multi-attribute-authenticator/blob/master/src/main/resources/how-to-try.gif" width="75%" title="how-to-configure"> 
