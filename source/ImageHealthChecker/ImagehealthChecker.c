/*
 * If not stated otherwise in this file or this component's LICENSE file
 * the following copyright and licenses apply:
 *
 * Copyright 2022 RDK Management
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

#include <ctype.h>
#include <syscfg/syscfg.h>

#include "ImagehealthChecker.h"
#include "ccsp_hal_ethsw.h"

int ccsp_hdl_ret;
int compare_pass(char *arg_type,char *curr_pass,char *dflt_pass,int old_value)
{
    // old value -- before reboot
    // 1 - no change in default 
    // 2 - change in default
    errno_t rc = -1;
    int ind = -1;
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), arg_type , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
         if(curr_pass[0] == '\0')
         {
             return -1;
         }
         rc = strcmp_s(curr_pass, 100, dflt_pass , &ind);
         ERR_CHK(rc);
         if((ind == 0) && (rc == EOK))
         {
            return 1; //current and default is same
         }
         else
         {
            return 2; //current and default is not same
         }
    }
    else //Bootup check
    {
        if(curr_pass[0] == '\0' || old_value == 0)
        {
            return -1; // old value should not be 0 either 1 or 2.
        }
        rc = strcmp_s(curr_pass, 100, dflt_pass , &ind);
        ERR_CHK(rc);
        if((ind == 0) && (rc == EOK) && old_value != 1)
        {
            return 1; //the previously configured passphrase is changed to default rather non factory reset case.
        }
    }
    IHC_PRINT("%s Previously configured passphrase/ssid and current are same \n",__FUNCTION__);
    return -1;
}
int Iscli_Wap_Pass_Changed(char *arg_type,int old_value,char *radio_type)
{
    int hdl_ret;
    errno_t rc = -1;
    int ind = -1;
    FILE *fp=NULL;
    char curr_pass_2g[100]={0};
    char curr_pass_5g[100]={0};
    char dflt_pass_2g[100]={0};
    char dflt_pass_5g[100]={0};
#ifdef _XB8_PRODUCT_REQ_
    char curr_pass_6g[100]={0};
    char dflt_pass_6g[100]={0};
#endif
    char TR181_buf[100]   ={0};
    if (strcmp_s("2G", strlen("2G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.1.Security.X_COMCAST-COM_KeyPassphrase",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 2G",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_pass_2g,100,TR181_buf);
            ERR_CHK(rc);
        }
        fp=v_secure_popen("r","psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.SSID.1.Passphrase");
        if (fp == NULL)
        {
            IHC_PRINT("%s popen failed 2G \n",__FUNCTION__);
        }
        else
        {
            fgets(dflt_pass_2g, 100, fp);
            rc = strcmp_s("", 1, dflt_pass_2g , &ind);
            ERR_CHK(rc);
            v_secure_pclose(fp);
            if(dflt_pass_2g[strlen(dflt_pass_2g)-1] == '\n')
            {
                dflt_pass_2g[strlen(dflt_pass_2g)-1] = '\0';
            }
            if((ind == 0) && (rc == EOK))
            {
                return -1;
            }
        }
        if (curr_pass_2g[0] != '\0' && dflt_pass_2g[0] != '\0')
        {
            return compare_pass(arg_type,curr_pass_2g,dflt_pass_2g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare passphrase failed due to either default or current passphrase value is null \n",__FUNCTION__);
            return -1;
        }
    }
    if (strcmp_s("5G", strlen("5G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.2.Security.X_COMCAST-COM_KeyPassphrase",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 5G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_pass_5g,100,TR181_buf);
            ERR_CHK(rc);
        }
        fp=v_secure_popen("r","psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.SSID.2.Passphrase");
        if (fp == NULL)
        {
            IHC_PRINT("%s popen failed 5G \n",__FUNCTION__);
        }
        else
        {
            fgets(dflt_pass_5g, 100, fp);
            rc = strcmp_s("", 1, dflt_pass_5g , &ind);
            ERR_CHK(rc);
            v_secure_pclose(fp);
            if(dflt_pass_5g[strlen(dflt_pass_5g)-1] == '\n')
            {
                dflt_pass_5g[strlen(dflt_pass_5g)-1] = '\0';
            }
            
            if((ind == 0) && (rc == EOK))
            {
                return -1;
            }
        }
        if (curr_pass_5g[0] != '\0' && dflt_pass_5g[0] != '\0')
        {
            return compare_pass(arg_type,curr_pass_5g,dflt_pass_5g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare passphrase failed due to either of default or current passphrase value is null \n",__FUNCTION__);
            return -1;
        }
    }
#ifdef _XB8_PRODUCT_REQ_   //XB8 only supports 6GHZ
    if (strcmp_s("6G", strlen("6G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.17.Security.X_COMCAST-COM_KeyPassphrase",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 6G \n",__FUNCTION__);
            return -1;
        }
        else
        {
            rc=strcpy_s(curr_pass_6g,100,TR181_buf);
            ERR_CHK(rc);
        }
        fp=v_secure_popen("r","psmcli get eRT.com.cisco.spvtg.ccsp.Device.WiFi.Radio.SSID.17.Passphrase");
        if (fp == NULL)
        {
            IHC_PRINT("%s popen failed 6G  \n",__FUNCTION__);
        }
        else
        {
            fgets(dflt_pass_6g, 100, fp);
            rc = strcmp_s("", 1, dflt_pass_6g , &ind);
            ERR_CHK(rc);
            v_secure_pclose(fp);
            if(dflt_pass_6g[strlen(dflt_pass_6g)-1] == '\n')
            {
                dflt_pass_6g[strlen(dflt_pass_6g)-1] = '\0';
            }
            if((ind == 0) && (rc == EOK))
            {
                return -1;
            }
        }
        if (curr_pass_6g[0] != '\0' && dflt_pass_6g[0] != '\0')
        {
            return compare_pass(arg_type,curr_pass_6g,dflt_pass_6g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare passphrase failed due to either of default or current passphrase value is null \n",__FUNCTION__);
            return -1;
        }
    }
#endif // _XB8_PRODUCT_REQ_ ends
    return -1;
}
int IS_SSID_Change_Private(char *arg_type,int old_value,char *radio_type)
{
    int hdl_ret;
    errno_t rc = -1;
    int ind = -1;
    char curr_ssid_2g[100]={0};
    char curr_ssid_5g[100]={0};
    char dflt_ssid_2g[100]={0};
    char dflt_ssid_5g[100]={0};
#ifdef _XB8_PRODUCT_REQ_
    char curr_ssid_6g[100]={0};
    char dflt_ssid_6g[100]={0};
#endif
    char TR181_buf[100]   ={0};
    if (strcmp_s("2G", strlen("2G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.1.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_ssid_2g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.1.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(dflt_ssid_2g,100,TR181_buf);
            ERR_CHK(rc);
        }
        if (curr_ssid_2g[0] != '\0' && dflt_ssid_2g[0] != '\0')
        {
            return compare_pass(arg_type,curr_ssid_2g,dflt_ssid_2g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
    if (strcmp_s("5G", strlen("5G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.2.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            CcspTraceError(("%s ccsp get failed 5G \n",__FUNCTION__));
        }
        else
        {
            rc=strcpy_s(curr_ssid_5g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.2.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 5G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(dflt_ssid_5g,100,TR181_buf);
            ERR_CHK(rc);
        }
        if (curr_ssid_5g[0] != '\0' && dflt_ssid_5g[0] != '\0')
        {
            return compare_pass(arg_type,curr_ssid_5g,dflt_ssid_5g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
#ifdef _XB8_PRODUCT_REQ_   //XB8 only supports 6GHZ
    if (strcmp_s("6G", strlen("6G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.17.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed failed for curr passphrase \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_ssid_6g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.17.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed failed for curr ssid \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(dflt_ssid_6g,100,TR181_buf);
            ERR_CHK(rc);
        }
        if (curr_ssid_6g[0] != '\0' && dflt_ssid_6g[0] != '\0')
        {
            return compare_pass(arg_type,curr_ssid_6g,dflt_ssid_6g,old_value);
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
#endif //_XB8_PRODUCT_REQ_ ends
    return -1;
}
int IS_SSID_Change_Public(char *arg_type,int old_value,char *radio_type)
{
    int hdl_ret;
    errno_t rc = -1;
    int ind = -1;
    char curr_ssid_2g[100]={0};
    char curr_ssid_5g[100]={0};
    char dflt_ssid_2g[100]={0};
    char dflt_ssid_5g[100]={0};
/*#ifdef _XB8_PRODUCT_REQ_ //XB8 won't support xifinity wifi on 6GHZ
    char curr_ssid_6g[100]={0};
    char dflt_ssid_6g[100]={0};
#endif*/
    char TR181_buf[100]   ={0};
    if (strcmp_s("2G", strlen("2G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.5.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_ssid_2g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.5.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(dflt_ssid_2g,100,TR181_buf);
            ERR_CHK(rc);
        }
        if (curr_ssid_2g[0] != '\0' && dflt_ssid_2g[0] != '\0')
        {
            if ( (strcmp_s("OutOfService", strlen("OutOfService"), curr_ssid_2g , &ind) == EOK) && !ind)
            {
                IHC_PRINT("%s Default SSID for xfinity hotspot is not changed \n",__FUNCTION__);
                if (old_value == 1)
                {
                    return 0; // Don't return 1 if previously configured also same as default
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                return compare_pass(arg_type,curr_ssid_2g,dflt_ssid_2g,old_value);
            }
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
    if (strcmp_s("5G", strlen("5G"), radio_type , &ind) == EOK && !ind)
    {
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.6.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 5G  \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(curr_ssid_5g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.6.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed 5G \n",__FUNCTION__);
        }
        else
        {
            rc=strcpy_s(dflt_ssid_5g,100,TR181_buf);
            ERR_CHK(rc);
        }
      
        if (curr_ssid_5g[0] != '\0' && dflt_ssid_5g[0] != '\0')
        {
            if ( (strcmp_s("OutOfService", strlen("OutOfService"), curr_ssid_5g , &ind) == EOK) && !ind )
            {
                IHC_PRINT("%s Default SSID for Xfinity hotspot is not changed \n",__FUNCTION__);
                if (old_value == 1)
                {
                    return 0; // Don't return 1 if previously configured also same as default
                }
                else
                {
                    return 1;
                }
            }
            else
            {
                return compare_pass(arg_type,curr_ssid_5g,dflt_ssid_5g,old_value);
            }
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
/* #ifdef _XB8_PRODUCT_REQ_   //XB8 won't support xifinity wifi on 6GHZ 
    if (strcmp_s("6G", strlen("6G"), radio_type , &ind) == EOK && !ind)
    {
        IHC_PRINT(" Enters IS_SSID_Change_Public 9 \n");
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.19.SSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed failed for curr passphrase \n",__FUNCTION__);
        }
        else
        {
            IHC_PRINT(" Enters IS_SSID_Change_Public 10 TR181_buf=%s  \n",TR181_buf);
            rc=strcpy_s(curr_ssid_6g,100,TR181_buf);
            ERR_CHK(rc);
        }
        memset(TR181_buf,0,sizeof(TR181_buf));
        hdl_ret=get_tr181param_value("Device.WiFi.SSID.19.X_COMCAST-COM_DefaultSSID",TR181_buf,100);
        if(hdl_ret !=0 )
        {
            IHC_PRINT("%s ccsp get failed for curr ssid \n",__FUNCTION__);
        }
        else
        {
            IHC_PRINT(" Enters IS_SSID_Change_Public 11 dfl_t_TR181_buf=%s \n",TR181_buf);
            rc=strcpy_s(dflt_ssid_6g,100,TR181_buf);
            ERR_CHK(rc);
        }
        
        if (curr_ssid_6g[0] != '\0' && dflt_ssid_6g[0] != '\0')
        {
            IHC_PRINT(" Enters IS_SSID_Change_Public 12 \n");
            if ( (strcmp_s("OutOfService", strlen("OutOfService"), curr_ssid_6g , &ind) == EOK) && !ind)
            {
                IHC_PRINT("%s Default SSID for public hotspot is not changed \n",__FUNCTION__);
                return -1;
            }
            else
            {
                return compare_pass(arg_type,curr_ssid_6g,dflt_ssid_6g,old_value);
            }
        }
        else
        {
            IHC_PRINT("%s Compare ssid failed due to either of default or current ssid value is null \n",__FUNCTION__);
            return -1;
        }
    }
#endif //_XB8_PRODUCT_REQ_ ends */
    return -1;
}
int IS_SSID_Change_SPublic(char *arg_type,int old_value,char *radio_type)
{
    // there will be no default SSID for secure hotspot.
    int hdl_ret;
    errno_t rc = -1;
    int ind = -1;
    char TR181_buf[100]={0};
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), arg_type , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        //2GHZ
        if (strcmp_s("2G", strlen("2G"), radio_type , &ind) == EOK && !ind)
        {
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.9.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
            }
            else
            {
                if ( ( (strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK) && !ind) || TR181_buf[0] == '\0' )
                {
                    IHC_PRINT("%s Default SSID for secure xfinity hotspot is not changed \n",__FUNCTION__);
                    return 1;
                }
                else
                {
                    return 2;
                }
            }
        }
        //5GHZ
        if (strcmp_s("5G", strlen("5G"), radio_type , &ind) == EOK && !ind)
        {
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.10.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed 5G \n",__FUNCTION__);
            }
            else
            {
                if ( ((strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK) && !ind) || TR181_buf[0] == '\0')
                {
                    IHC_PRINT("%s Default SSID for secure xfinity hotspot is not changed \n",__FUNCTION__);
                    return 1;
                }
                else
                {
                    return 2;
                }
            }
        }
/*#ifdef _XB8_PRODUCT_REQ_   //XB8 only supports 6GHZ //XB8 won't support secure xifinity wifi on 6GHZ
        if (strcmp_s("6G", strlen("6G"), radio_type , &ind) == EOK && !ind)
        {
        //6GHZ
            IHC_PRINT(" Enters IS_SSID_Change_SPublic 5 \n");
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.19.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed failed for curr ssid \n",__FUNCTION__);
            }
            else
            {
                IHC_PRINT(" Enters IS_SSID_Change_SPublic 6 TR181_buf=%s \n",TR181_buf);
                if ( ((strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK) && !ind) || TR181_buf[0] == '\0')
                {
                    IHC_PRINT("%s Default SSID for secure hotspot is not changed \n",__FUNCTION__);
                    return 1;
                }
                else
                {
                    return 2;
                }
            }
        }
#endif //_XB8_PRODUCT_REQ_ ends */
    }
    else //Bootup check
    {
        //2GHZ
        if (strcmp_s("2G", strlen("2G"), radio_type , &ind) == EOK && !ind)
        {
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.9.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed 2G \n",__FUNCTION__);
            }
            else
            {
                if ( (((strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK) && !ind) || TR181_buf[0] == '\0') && old_value == 2 )
                {
                    IHC_PRINT("%s SSID for secure xfinity hotspot is changed to default from previously configured \n",__FUNCTION__);
                    return 1;
                }
                return 0;
            }
        }
        //5GHZ
        if (strcmp_s("5G", strlen("5G"), radio_type , &ind) == EOK && !ind)
        {
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.10.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed 5G \n",__FUNCTION__);
            }
            else
            {
                if ( (((strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK) && !ind) || TR181_buf[0] == '\0' ) && old_value == 2 )
                {
                    IHC_PRINT("%s SSID for secure xfinity hotspot is changed to default from previously configured \n",__FUNCTION__);
                    return 1;
                }
                return 0;
            }
        }
/*#ifdef _XB8_PRODUCT_REQ_   //XB8 only supports 6GHZ //XB8 won't support secure xifinity wifi on 6GHZ
        if (strcmp_s("6G", strlen("6G"), radio_type , &ind) == EOK && !ind)
        {
            IHC_PRINT(" Enters IS_SSID_Change_SPublic 11 \n");
        //6GHZ
            hdl_ret=get_tr181param_value("Device.WiFi.SSID.21.SSID",TR181_buf,100);
            if(hdl_ret !=0 )
            {
                IHC_PRINT("%s ccsp get failed failed for curr ssid \n",__FUNCTION__);
            }
            else
            {
                IHC_PRINT(" Enters IS_SSID_Change_SPublic 12 TR181_buf=%s",TR181_buf);
                if ( (strcmp_s("OutOfService", strlen("OutOfService"), TR181_buf , &ind) == EOK || strcmp_s("", 1, TR181_buf , &ind) == EOK ) && old_value == 2 )
                {
                    IHC_PRINT("%s SSID for secure hotspot is changed to default from previously configured \n",__FUNCTION__);
                    return 1;
                }
                return 0;
            }
        }
#endif //_XB8_PRODUCT_REQ_ ends */
    }
    return -1;
}
void get_Clients_Count(char * arg_type,char * ret_buf,int size)   //Need to run this logic in the script
{
   char TR181_buf[3]={0};
   char G2_count[3]={0};
   char G5_count[3]={0};
#ifdef _XB8_PRODUCT_REQ_ 
   char G6_count[3]={0};
#endif
   int hdl_ret;
   char sys_cfg_store[30] = {0};
   char eth_cli_cnt[3]={0};
   errno_t rc = -1;
   int ind = -1;
   int ret_val=-1;
   unsigned long total_eth_device = 0;
   eth_device_t *output_struct = NULL;
   hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.1.AssociatedDeviceNumberOfEntries",TR181_buf,3);
   if(hdl_ret !=0 )
   {
       IHC_PRINT("%s ccsp get failed 2G,Assigning 0 to the client counts \n",__FUNCTION__);
       rc=strcpy_s(G2_count,3,"0");
       ERR_CHK(rc);
   }
   else
   {
      rc=strcpy_s(G2_count,3,TR181_buf);
      IHC_PRINT("%s No of clients connected to 2G interface is %s \n",__FUNCTION__,G2_count);
      ERR_CHK(rc);
   }
   hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.2.AssociatedDeviceNumberOfEntries",TR181_buf,3);
   if(hdl_ret !=0 )
   {
       IHC_PRINT("%s ccsp get failed 5G,Assigning 0 to the client counts \n",__FUNCTION__);
       rc=strcpy_s(G5_count,3,"0");
       ERR_CHK(rc);
   }
   else
   {
      rc=strcpy_s(G5_count,3,TR181_buf);
      IHC_PRINT("%s No of clients connected to 5G interface is %s \n",__FUNCTION__,G5_count);
      ERR_CHK(rc);
   }
#ifdef _XB8_PRODUCT_REQ_ 
   hdl_ret=get_tr181param_value("Device.WiFi.AccessPoint.17.AssociatedDeviceNumberOfEntries",TR181_buf,3);
   if(hdl_ret !=0 )
   {
       IHC_PRINT("%s ccsp get failed 6G,Assigning 0 to the client counts \n",__FUNCTION__);
       rc=strcpy_s(G6_count,3,"0");
       ERR_CHK(rc);
   }
   else
   {
      rc=strcpy_s(G6_count,3,TR181_buf);
      IHC_PRINT("%s No of clients connected to 6G interface is %s \n",__FUNCTION__,G6_count);
      ERR_CHK(rc);
   }
#endif
   // sky platforms not supporting ethi_api tool, so using  the generic way CcspHalExtSw_getAssociatedDevice api
   ret_val = CcspHalExtSw_getAssociatedDevice(&total_eth_device, &output_struct);
   if (0 != ret_val)
   {
       IHC_PRINT("%s CcspHalExtSw_getAssociatedDevice failed, So assigning 0 to the ethernet clients\n", __FUNCTION__);
       total_eth_device=0;
   }
   else
   {
       IHC_PRINT("%s CcspHalExtSw_getAssociatedDevice returns total_eth_device=%lu \n",__FUNCTION__,total_eth_device);
   }
   rc = sprintf_s(eth_cli_cnt, sizeof(eth_cli_cnt), "%lu", total_eth_device);
   if(rc < EOK)
   {
       ERR_CHK(rc);
   }
   IHC_PRINT("%s No of clients connected to ETH interface is %s \n",__FUNCTION__,eth_cli_cnt);
#ifdef _XB8_PRODUCT_REQ_ 
   rc = sprintf_s(sys_cfg_store,sizeof(sys_cfg_store),"2g-%s,5g-%s,6g-%s,eth-%s",G2_count,G5_count,G6_count,eth_cli_cnt);
#else
   rc = sprintf_s(sys_cfg_store,sizeof(sys_cfg_store),"2g-%s,5g-%s,eth-%s",G2_count,G5_count,eth_cli_cnt);
#endif
   if(rc < EOK)
   {
       ERR_CHK(rc);
   }
   IHC_PRINT(" syscfg store value is =%s \n",sys_cfg_store);
   rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), arg_type , &ind);
   ERR_CHK(rc);
   if((ind == 0) && (rc == EOK))
   {
       if (syscfg_set_commit(NULL, "IHC_Clients_count", sys_cfg_store) != 0 )
       {
           IHC_PRINT("%s syscfg_set failed \n",__FUNCTION__);
       }
   }
   else
   {
       //return the current value for bootup check
       rc = strcpy_s(ret_buf,size,sys_cfg_store);
       ERR_CHK(rc);
   }
}
void Check_ConnCli_Count(char * arg)
{
    int iszero_cli=0;
    errno_t rc = -1;
    int ind    = -1;
    char cli_cnt_buf[30]={0};
    char old_cli_cnt[30]={0};
#ifdef _XB8_PRODUCT_REQ_
    int g6_c_old=0,g6_c=0;
#endif
    int g2_c_old=0,g5_c_old=0,eth_c_old=0;
    int g2_c=0,g5_c=0,eth_c=0;
    int ret=0;
    //store-health block
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), arg , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
       get_Clients_Count(STR_HLTH,NULL,0);
    }
    //boot-up check block
    rc = strcmp_s(BT_CHCK, strlen(BT_CHCK), arg , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
       get_Clients_Count(BT_CHCK,cli_cnt_buf,30);
       
       //Get 2.5G,5G,6G old clients counts
       if(!syscfg_get( NULL, "IHC_Clients_count" , old_cli_cnt, sizeof(old_cli_cnt)))
       {
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
           ret=sscanf(old_cli_cnt,"2g-%d,5g-%d,6g-%d,eth-%d",&g2_c_old,&g5_c_old,&g6_c_old,&eth_c_old);
#else
           ret=sscanf(old_cli_cnt,"2g-%d,5g-%d,eth-%d",&g2_c_old,&g5_c_old,&eth_c_old);
#endif
           if(ret < 1)
           {
               IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
               return;
           }
       }
       else
       {
           IHC_PRINT("%s syscfg get failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
        
       //Get 2.5G,5G,6G new clients counts
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
       ret=sscanf(cli_cnt_buf,"2g-%d,5g-%d,6g-%d,eth-%d",&g2_c,&g5_c,&g6_c,&eth_c);
#else
       ret=sscanf(cli_cnt_buf,"2g-%d,5g-%d,eth-%d",&g2_c,&g5_c,&eth_c);
#endif
       if(ret < 1)
       {
           IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
       //Compare the client counts and find the difference
       //2GHZ
       ret=fnd_cli_diff(g2_c_old,g2_c);
       if(g2_c_old != 0 && g2_c == 0)
       {
           report_t2("IHC:ConnectedPrivateClientsZero_Radio2.4G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsZero_Radio2.4G: %s\n","TRUE");
           iszero_cli=1;
       }
       if(ret <= 60 && iszero_cli != 1 && ret != -1)
       {
           report_t2("IHC:ConnectedPrivateClientsBelow60P_Radio2.4G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsBelow60P_Radio2.4G:%s \n","TRUE");
       }
       iszero_cli=0;
       //5GHZ
       ret=fnd_cli_diff(g5_c_old,g5_c);
       if(g5_c_old != 0 && g5_c == 0 )
       {
           report_t2("IHC:ConnectedPrivateClientsZero_Radio5G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsZero_Radio5G:%s \n","TRUE");
           iszero_cli=1;
       }
       if(ret <= 60 && iszero_cli != 1 && ret != -1)
       {
           report_t2("IHC:ConnectedPrivateClientsBelow60P_Radio5G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsBelow60P_Radio5G:%s \n","TRUE");
       }
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
       iszero_cli=0;
       //6GHZ
       ret=fnd_cli_diff(g6_c_old,g6_c);
       if(g6_c_old != 0 && g6_c == 0)
       {
           report_t2("IHC:ConnectedPrivateClientsZero_Radio6G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsZero_Radio6G:%s \n","TRUE");
           iszero_cli=1;
       }
       if(ret <= 60 && iszero_cli != 1 && ret != -1)
       {
           report_t2("IHC:ConnectedPrivateClientsBelow60P_Radio6G",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsBelow60P_Radio6G:%s \n","TRUE");
       }
#endif  //_XB8_PRODUCT_REQ_ ends
       iszero_cli=0;
       //ETHERNET
       ret=fnd_cli_diff(eth_c_old,eth_c);
       if(eth_c_old != 0 && eth_c == 0)
       {
           report_t2("IHC:ConnectedPrivateClientsZero_RadioETH",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsZero_RadioETH:%s \n","TRUE");
           iszero_cli=1;
       }
       if(ret <= 60 && iszero_cli != 1 && ret != -1)
       {
           report_t2("IHC:ConnectedPrivateClientsBelow60P_RadioETH",'s',"TRUE");
           IHC_PRINT("IHC:ConnectedPrivateClientsBelow60P_RadioETH:%s \n","TRUE");
       }
    }
}
void Check_Pwd_Change(char * call_type)
{
    int Ret_2g=0,Ret_5g=0;
#ifdef _XB8_PRODUCT_REQ_
    int Ret_6g=0;
    int Ret_6g_old;
#endif
    char old_val[30]={0};
    errno_t rc = -1;
    int ret;
    int  Ret_2g_old,Ret_5g_old;
    int ind    = -1;
    //store-health
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), call_type , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        //2GHZ
        ret=Iscli_Wap_Pass_Changed(call_type,0,"2G");
        if(-1 != ret) 
        {
            Ret_2g=ret;
        }
        else
        {
            IHC_PRINT("%s passphrase Comparison for 2g failed \n",__FUNCTION__);
        }
        //5GHZ
        ret=Iscli_Wap_Pass_Changed(call_type,0,"5G");
        if(-1 != ret)
        {
            Ret_5g=ret;
        }
        else
        {
            IHC_PRINT("%s passphrase Comparison for 5g failed \n",__FUNCTION__);
        }
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        //6GHZ
        ret=Iscli_Wap_Pass_Changed(call_type,0,"6G");
        if(-1 != ret)
        {
            Ret_6g=ret;
        }
        else
        {
            IHC_PRINT("%s passphrase Comparison for 6g failed \n",__FUNCTION__);
        }
#endif // ends _XB8_PRODUCT_REQ_
        //setting the old values in syscfg db
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        rc = sprintf_s(old_val, sizeof(old_val), "2g-%d,5g-%d,6g-%d",Ret_2g,Ret_5g,Ret_6g);
#else
        rc = sprintf_s(old_val, sizeof(old_val), "2g-%d,5g-%d",Ret_2g,Ret_5g);
#endif
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(syscfg_set_commit(NULL,"IHC_pass_change",old_val)!=0)
        {
            IHC_PRINT("%s: syscfg_set failed \n ", __FUNCTION__);
            return;
        }
    }
    else
    {
       if(!syscfg_get( NULL, "IHC_pass_change" , old_val, sizeof(old_val)))
       {
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
           ret=sscanf(old_val,"2g-%d,5g-%d,6g-%d",&Ret_2g_old,&Ret_5g_old,&Ret_6g_old);
#else
           ret=sscanf(old_val,"2g-%d,5g-%d",&Ret_2g_old,&Ret_5g_old);
#endif
           if(ret < 1)
           {
               IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
               return;
           }
       }
       else
       {
           IHC_PRINT("%s syscfg get failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
        //2GHZ
       if(Ret_2g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
           ret=Iscli_Wap_Pass_Changed(call_type,Ret_2g_old,"2G");
           if(-1 != ret)
           {
              if(ret == 1) // if there is any change in default
              {
                  report_t2("IHC:AuthenticationConfigChanged_WAPInstance2.4G",'s',"TRUE");
                  IHC_PRINT("IHC:AuthenticationConfigChanged_WAPInstance2.4G:%s \n","TRUE");
              }
           }
           else
           {
              IHC_PRINT("%s passphrase Comparison for 2g failed due to either value is null or passpharse not changed \n",__FUNCTION__);
           }
       }
       else
       {
           IHC_PRINT("%s passphrase Comparison for 2g failed \n",__FUNCTION__);
       }
        //5GHZ
       if(Ret_5g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=Iscli_Wap_Pass_Changed(call_type,Ret_5g_old,"5G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:AuthenticationConfigChanged_WAPInstance5G",'s',"TRUE");
                    IHC_PRINT("IHC:AuthenticationConfigChanged_WAPInstance5G:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s passphrase Comparison for 5g failed due to either value is null or passpharse not changed\n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s passphrase Comparison for 5g failed \n",__FUNCTION__);
       }
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        //6GHZ
       if(Ret_6g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=Iscli_Wap_Pass_Changed(call_type,Ret_6g_old,"6G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:AuthenticationConfigChanged_WAPInstance6G",'s',"TRUE");
                    IHC_PRINT("IHC:AuthenticationConfigChanged_WAPInstance6G:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s passphrase Comparison for 6g failed due to either value is null or passpharse not changed \n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s passphrase Comparison for 6g failed \n",__FUNCTION__);
       }
#endif  //_XB8_PRODUCT_REQ_ ends
    }
}
void Check_SSID_Change(char *call_type)
{
    int Ret_2g=0,Ret_5g=0;
#ifdef _XB8_PRODUCT_REQ_
    int Ret_6g=0;
    int Ret_6g_old;
#endif
    char buff[30]={0};
    errno_t rc = -1;
    int ret;
    int  Ret_2g_old,Ret_5g_old;
    int ind    = -1;
    //store-health
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), call_type , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        //SSID private
        //2GHZ
        ret=IS_SSID_Change_Private(call_type,0,"2G");
        if(-1 != ret) 
        {
            Ret_2g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
        }
        //5GHZ
        ret=IS_SSID_Change_Private(call_type,0,"5G");
        if(-1 != ret)
        {
            Ret_5g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
        }
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        //6GHZ
        ret=IS_SSID_Change_Private(call_type,0,"6G");
        if(-1 != ret)
        {
            Ret_6g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 6g failed \n",__FUNCTION__);
        }
#endif
        //setting the old values in syscfg db
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        rc = sprintf_s(buff, sizeof(buff), "2g-%d,5g-%d,6g-%d",Ret_2g,Ret_5g,Ret_6g);
#else
        rc = sprintf_s(buff, sizeof(buff), "2g-%d,5g-%d",Ret_2g,Ret_5g);
#endif
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(syscfg_set_commit(NULL,"IHC_ssid_change_private",buff)!=0)
        {
            IHC_PRINT("%s: syscfg_set failed  \n", __FUNCTION__);
            //return;
        }
        Ret_2g=0;
        Ret_5g=0;
        memset(buff,0,sizeof(buff));
        
        //SSID_PUBLIC
        ret=IS_SSID_Change_Public(call_type,0,"2G");
        if(-1 != ret) 
        {
            Ret_2g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
        }
        //5GHZ
        ret=IS_SSID_Change_Public(call_type,0,"5G");
        if(-1 != ret)
        {
            Ret_5g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
        }
/*#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ XB8 won't support xifinity wifi on 6GHZ
        //6GHZ
        ret=IS_SSID_Change_Public(call_type,0,"6G");
        IHC_PRINT(" Enters Check_SSID_Change 8 ret=%d \n",ret);
        if(-1 != ret)
        {
            Ret_6g=ret;
        }
        else
        {
            IHC_PRINT("ssid Comparison for 6g failed \n");
        }
#endif*/
        //setting the old values in syscfg db
        rc = sprintf_s(buff, sizeof(buff), "2g-%d,5g-%d",Ret_2g,Ret_5g);
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(syscfg_set_commit(NULL,"IHC_ssid_change_public",buff)!=0)
        {
            IHC_PRINT("%s: syscfg_set failed \n ", __FUNCTION__);
            return;
        }
        //SSID SPUBLIC
        Ret_2g=0;
        Ret_5g=0;
        memset(buff,0,sizeof(buff));
        //SSID_PUBLIC
        ret=IS_SSID_Change_SPublic(call_type,0,"2G");
        if(-1 != ret) 
        {
            Ret_2g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
        }
        //5GHZ
        ret=IS_SSID_Change_SPublic(call_type,0,"5G");
        if(-1 != ret)
        {
            Ret_5g=ret;
        }
        else
        {
            IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
        }
/* #ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ XB8 won't support xifinity wifi on 6GHZ
        //6GHZ
        ret=IS_SSID_Change_SPublic(call_type,0,"6G");
        IHC_PRINT(" Enters Check_SSID_Change 12 ret=%d \n",ret);
        if(-1 != ret)
        {
            Ret_6g=ret;
        }
        else
        {
            IHC_PRINT("ssid Comparison for 6g failed \n");
        }
        //setting the old values in syscfg db
        //XB8 only supports 6GHZ
        rc = sprintf_s(buff, sizeof(buff), "2g-%d,5g-%d,6g-%d",Ret_2g,Ret_5g,Ret_6g);
#else */
        rc = sprintf_s(buff, sizeof(buff), "2g-%d,5g-%d",Ret_2g,Ret_5g);
//#endif
        if(rc < EOK)
        {
            ERR_CHK(rc);
        }
        if(syscfg_set_commit(NULL,"IHC_ssid_change_spublic",buff)!=0)
        {
            IHC_PRINT("%s: syscfg_set failed \n ", __FUNCTION__);
            return;
        }
    }
    else
    {
       memset(buff,0,sizeof(buff));
       //SSID PRIVATE
       if((!syscfg_get( NULL, "IHC_ssid_change_private" , buff, sizeof(buff))) && buff[0] != '\0')
       {
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
           ret=sscanf(buff,"2g-%d,5g-%d,6g-%d",&Ret_2g_old,&Ret_5g_old,&Ret_6g_old);
#else
           ret=sscanf(buff,"2g-%d,5g-%d",&Ret_2g_old,&Ret_5g_old);
#endif
           if(ret < 1)
           {
               IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
               return;
           }
       }
       else
       {
           IHC_PRINT("%s syscfg get failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
        //2GHZ
       if(Ret_2g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
           ret=IS_SSID_Change_Private(call_type,Ret_2g_old,"2G");
           if(-1 != ret)
           {
              if(ret == 1) // if there is any change in default
              {
                  report_t2("IHC:SSIDChanged_WAPInstance2.4G_PRIV",'s',"TRUE");
                  IHC_PRINT("IHC:SSIDChanged_WAPInstance2.4G_PRIV:%s \n","TRUE");
              }
           }
           else
           {
              IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
           }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
       }
        //5GHZ
       if(Ret_5g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_Private(call_type,Ret_5g_old,"5G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance5G_PRIV",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance5G_PRIV:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
       }
#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ
        //6GHZ
       if(Ret_6g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_Private(call_type,Ret_6g_old,"6G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance6G_PRIV",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance6G_PRIV:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s ssid Comparison for 6g failed \n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 6g failed \n",__FUNCTION__);
       }
#endif //XB8 ends
       //SSID PUBLIC
       memset(buff,0,sizeof(buff));
       Ret_2g_old=0;
       Ret_5g_old=0;
       if(!syscfg_get( NULL, "IHC_ssid_change_public" , buff, sizeof(buff)))
       {
           ret=sscanf(buff,"2g-%d,5g-%d",&Ret_2g_old,&Ret_5g_old);
           if(ret < 1)
           {
               IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
               return;
           }
       }
       else
       {
           IHC_PRINT("%s syscfg get failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
        //2GHZ
       if(Ret_2g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
           ret=IS_SSID_Change_Public(call_type,Ret_2g_old,"2G");
           if(-1 != ret)
           {
              if(ret == 1)
              {
                  report_t2("IHC:SSIDChanged_WAPInstance2.4G_PUBLIC",'s',"TRUE");
                  IHC_PRINT("IHC:SSIDChanged_WAPInstance2.4G_PUBLIC:%s \n","TRUE");
              }
           }
           else
           {
              IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
           }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
       }
        //5GHZ
       if(Ret_5g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_Public(call_type,Ret_5g_old,"5G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance5G_PUBLIC",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance5G_PUBLIC:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
       }
/*#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ //XB8 won't support xifinity wifi on 6GHZ
        //6GHZ
       if(Ret_6g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_Public(call_type,Ret_6g_old,"6G");
            IHC_PRINT(" Enters Check_SSID_Change 22 ret=%d \n",ret);
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance{6G_PUBLIC}",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance{6G_PUBLIC}:%d \n",ret);
                }
            }
            else
            {
                IHC_PRINT("ssid Comparison for 6g failed \n");
            }
       }
       else
       {
           IHC_PRINT("ssid Comparison for 6g failed \n");
       }
#endif //XB8 ends */
       //SSID SPUBLIC
       memset(buff,0,sizeof(buff));
       Ret_2g_old=0;
       Ret_5g_old=0;
       if(!syscfg_get( NULL, "IHC_ssid_change_spublic" , buff, sizeof(buff)))
       {
           ret=sscanf(buff,"2g-%d,5g-%d",&Ret_2g_old,&Ret_5g_old);
           if(ret < 1)
           {
               IHC_PRINT("%s sscanf Failed,Unable to compare the values \n",__FUNCTION__);
               return;
           }
       }
       else
       {
           IHC_PRINT("%s syscfg get failed,Unable to compare the values \n",__FUNCTION__);
           return;
       }
        //2GHZ
       if(Ret_2g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
           ret=IS_SSID_Change_SPublic(call_type,Ret_2g_old,"2G");
           if(-1 != ret)
           {
              if(ret == 1) // if there is any change in default
              {
                  report_t2("IHC:SSIDChanged_WAPInstance2.4G_SPUBLIC",'s',"TRUE");
                  IHC_PRINT("IHC:SSIDChanged_WAPInstance2.4G_SPUBLIC:%s \n","TRUE");
              }
           }
           else
           {
              IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
           }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 2g failed \n",__FUNCTION__);
       }
        //5GHZ
       if(Ret_5g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_SPublic(call_type,Ret_5g_old,"5G");
            if(-1 != ret)
            {
                if(ret == 1) // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance5G_SPUBLIC",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance5G_SPUBLIC:%s \n","TRUE");
                }
            }
            else
            {
                IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
            }
       }
       else
       {
           IHC_PRINT("%s ssid Comparison for 5g failed \n",__FUNCTION__);
       }
/*#ifdef _XB8_PRODUCT_REQ_  //XB8 only supports 6GHZ //XB8 won't support xifinity wifi on 6GHZ
        //6GHZ
       if(Ret_6g_old != 0) // there were no data taken previous to the bootup due to some errors
       {
            ret=IS_SSID_Change_SPublic(call_type,Ret_6g_old,"6G");
            IHC_PRINT(" Enters Check_SSID_Change 26 ret=%d \n",ret);
            if(-1 != ret)
            {
                if(ret == 1)  // if there is any change in default
                {
                    report_t2("IHC:SSIDChanged_WAPInstance{6G_SPUBLIC}",'s',"TRUE");
                    IHC_PRINT("IHC:SSIDChanged_WAPInstance{6G_SPUBLIC}:%d \n",ret);
                }
            }
            else
            {
                IHC_PRINT(("ssid Comparison for 6g failed \n"));
            }
       }
       else
       {
           IHC_PRINT(("ssid Comparison for 6g failed \n"));
       }
#endif //XB8 ends */
    }
}
void Check_PODs_Conn(char *call_type)
{
    int ind    = -1;
    char cli_mac_2g[200]={0};
    char cli_mac_5g[200]={0};
    char cli_mac_2g_old[200]={0};
    char cli_mac_5g_old[200]={0};
    char cli_mac_eth[200]={0};
    char cli_mac_eth_old[200]={0};
    char tmp_buf[200]={0};
    char pod_eth_mac[200]={0};
    char tele_buff[200]={0};
    char *token=NULL;
    errno_t rc = -1;
    int str_fnd;
    int iter;
    char TR181_buf[200]={0};
    FILE *fp=NULL;
    rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), call_type , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))       //store-health
    {
        //2GHZ
        fp = v_secure_popen("r","wifi_api wifi_getApAssociatedDeviceDiagnosticResult 12 | grep -i cli_MACAddress | sed 's,.*\\(.\\{17\\}\\)$,\\1,' | awk '{print}' ORS=' '");
        if(fp != NULL)
        {
            fgets(cli_mac_2g,200,fp);
            v_secure_pclose(fp);
        }
        if( cli_mac_2g[0] != '\0' && syscfg_set_commit(NULL, "IHC_2G_MAC_POD", cli_mac_2g) != 0 )
        {
            IHC_PRINT("%s syscfg_set failed \n",__FUNCTION__);
        }
        
        //5GHZ
        fp = v_secure_popen("r","wifi_api wifi_getApAssociatedDeviceDiagnosticResult 13 | grep -i cli_MACAddress | sed 's,.*\\(.\\{17\\}\\)$,\\1,' | awk '{print}' ORS=' '");
        if(fp != NULL)
        {
            fgets(cli_mac_5g,200,fp);
            v_secure_pclose(fp);
        }
        if(cli_mac_5g[0] != '\0' && syscfg_set_commit(NULL, "IHC_5G_MAC_POD", cli_mac_5g) != 0 )
        {
            IHC_PRINT("%s syscfg_set failed \n",__FUNCTION__);
        }
        //ETHERNET-BACKHAUL
        if(syscfg_get( NULL, "opensync" , tele_buff, sizeof(tele_buff))!=0) // tele_buff is used to get opensync enable/disable here
        {
           IHC_PRINT("%s syscfg get failed,Unable to get ETHERNET POD details \n",__FUNCTION__);
        }
        
        if(syscfg_get( NULL, "opensync" , tele_buff, sizeof(tele_buff))!=0) // tele_buff is used to get opensync enable/disable here
        {
           IHC_PRINT("%s syscfg get failed,Unable to get ETHERNET POD details \n",__FUNCTION__);
        }
        if (strcmp_s("true", strlen("true"), tele_buff , &ind) == EOK && !ind)
        {
            fp = v_secure_popen("r","/usr/opensync/tools/ovsh s Node_Config | grep -i value | cut -d'|' -f2 | sed 's/,/ /g' | sed -r 's/[^ ]{2}/&:/g' | sed 's/: / /g'");
            if(fp != NULL)
            {
                fgets(pod_eth_mac,200,fp);
                v_secure_pclose(fp);
            }
        }
        else
        {
            fp = v_secure_popen("r","/usr/plume/tools/ovsh s Node_Config | grep -i value | cut -d'|' -f2 | sed 's/,/ /g' | sed -r 's/[^ ]{2}/&:/g' | sed 's/: / /g'");
            if(fp != NULL)
            {
                fgets(pod_eth_mac,200,fp);
                v_secure_pclose(fp);
            }
        }
        for(iter=1;iter<=4;iter++)
        {
            memset(tele_buff,0,sizeof(tele_buff));
//            hdl_ret=get_tr181param_value(tele_buff,TR181_buf,200);
            fp = v_secure_popen("r","dmcli eRT getv Device.Ethernet.Interface.%d.X_RDKCENTRAL-COM_AssociatedDevice. | grep 'value:' |  sed 's/^.*: //' | awk '{print}' ORS=' '",iter);
            if(fp != NULL)
            {
                fgets(tele_buff,200,fp);
                v_secure_pclose(fp);
            }
            if(tele_buff[0] == '\0' )
            {
                IHC_PRINT("%s ccsp get failed or no values from the dmcli \n",__FUNCTION__);
                continue;
            }
            else
            {
                for(iter=0;iter<strlen(tele_buff);iter++)
                {
                    TR181_buf[iter]=tolower(tele_buff[iter]);
                }
                TR181_buf[iter]='\0';
                token=strtok(TR181_buf," ");
                while((token != NULL))
                {
                    if(strstr(pod_eth_mac,token))
                    {
                        rc = strcat_s(cli_mac_eth, sizeof(cli_mac_eth), token);
                        ERR_CHK(rc);
                        rc = strcat_s(cli_mac_eth, sizeof(cli_mac_eth), " ");
                        ERR_CHK(rc);
                    }
                    token=strtok(NULL," ");
                }
           }
        }
        if(cli_mac_eth[0] != '\0' && syscfg_set_commit(NULL, "IHC_ETH_MAC_POD", cli_mac_eth) != 0 )
        {
            IHC_PRINT("%s syscfg_set failed \n",__FUNCTION__);
        }
        //6GHZ 
        /* POD is not implemented in 6GHZ interface */
    }
    else // bootup-check
    {
        //2GHZ
       if(syscfg_get( NULL, "IHC_2G_MAC_POD" , cli_mac_2g_old, sizeof(cli_mac_2g_old))!=0)
       {
           IHC_PRINT("%s syscfg get failed,Unable to get 2G POD details \n",__FUNCTION__);
       }
       //5GHZ
       if(syscfg_get( NULL, "IHC_5G_MAC_POD" , cli_mac_5g_old, sizeof(cli_mac_5g_old))!=0)
       {
           IHC_PRINT("%s syscfg get failed,Unable to get 5G POD details \n",__FUNCTION__);
       }
        //2GHZ
        fp = v_secure_popen("r","wifi_api wifi_getApAssociatedDeviceDiagnosticResult 12 | grep -i cli_MACAddress | sed 's,.*\\(.\\{17\\}\\)$,\\1,' | awk '{print}' ORS=' '");
        if(fp != NULL)
        {
            fgets(cli_mac_2g,200,fp);
            v_secure_pclose(fp);
        }
        //5GHZ
        fp = v_secure_popen("r","wifi_api wifi_getApAssociatedDeviceDiagnosticResult 13 | grep -i cli_MACAddress | sed 's,.*\\(.\\{17\\}\\)$,\\1,' | awk '{print}' ORS=' '");
        if(fp != NULL)
        {
            fgets(cli_mac_5g,200,fp);
            v_secure_pclose(fp);
        }
        //ETHERNET
        if(syscfg_get( NULL, "opensync" , tele_buff, sizeof(tele_buff))!=0) // tele_buff is used to get opensync enable/disable here
        {
           IHC_PRINT("%s syscfg get failed,Unable to get ETHERNET POD details \n",__FUNCTION__);
        }
        if (strcmp_s("true", strlen("true"), tele_buff , &ind) == EOK && !ind)
        {
            fp = v_secure_popen("r","/usr/opensync/tools/ovsh s Node_Config | grep -i value | cut -d'|' -f2 | sed 's/,/ /g' | sed -r 's/[^ ]{2}/&:/g' | sed 's/: / /g'");
            if(fp != NULL)
            {
                fgets(pod_eth_mac,200,fp);
                v_secure_pclose(fp);
            }
        }
        else
        {
            fp = v_secure_popen("r","/usr/plume/tools/ovsh s Node_Config | grep -i value | cut -d'|' -f2 | sed 's/,/ /g' | sed -r 's/[^ ]{2}/&:/g' | sed 's/: / /g'");
            if(fp != NULL)
            {
                fgets(pod_eth_mac,200,fp);
                v_secure_pclose(fp);
            }
        }
        for(iter=1;iter<=4;iter++)
        {
            memset(tele_buff,0,sizeof(tele_buff));
            fp = v_secure_popen("r","dmcli eRT getv Device.Ethernet.Interface.%d.X_RDKCENTRAL-COM_AssociatedDevice. | grep 'value:' |  sed 's/^.*: //' | awk '{print}' ORS=' '",iter);
            if(fp != NULL)
            {
                fgets(tele_buff,200,fp);
                v_secure_pclose(fp);
            }
            else
            {
                IHC_PRINT("%s Unable to open fp \n",__FUNCTION__);
                continue;
            }
            if(tele_buff[0] == '\0' )
            {
                IHC_PRINT("%s No device connected to the Eth interface at port %d \n",__FUNCTION__,iter);
                continue;
            }
            else
            {
                for(iter=0;iter<strlen(tele_buff);iter++)
                {
                    TR181_buf[iter]=tolower(tele_buff[iter]);
                }
                TR181_buf[iter]='\0';
                token=strtok(TR181_buf," ");
                while(token != NULL)
                {
                    if(strstr(pod_eth_mac,token))
                    {
                        rc = strcat_s(cli_mac_eth, sizeof(cli_mac_eth), token);
                        ERR_CHK(rc);
                        rc = strcat_s(cli_mac_eth, sizeof(cli_mac_eth), " ");
                        ERR_CHK(rc);
                    }
                    token=strtok(NULL," ");
                }
            }
        }
        memset(tele_buff,0,sizeof(tele_buff));
//2GHZ  to check if pods connected to 2g before reboot is connected back to device after reboot or not
        if( cli_mac_2g[0] != '\0' )
        {
            if ( cli_mac_2g_old[0] != '\0' )
            {
                rc=strcpy_s(tmp_buf,200,cli_mac_2g_old);
                ERR_CHK(rc);
                token = strtok(tmp_buf, " ");
                while(token != NULL)
                {
                    str_fnd=0;
                    if(strstr(cli_mac_2g,token))
                    {
                        IHC_PRINT(" %s POD %s is connected to 2.4G interface before and after reboot  \n",__FUNCTION__,token);
                        IHC_PRINT("\n IHC:WirelessPOD_Radio2.4G_POD:%s \n",token);
                        report_t2("IHC:WirelessPOD_Radio2.4G_POD",'s',token);
                        str_fnd=1;
                    }
                    if(str_fnd == 0)                 // Checking whether the client is connected to 5GHZ after reboot
                    {
                        IHC_PRINT("Client %s is not connected to 2.4G after reboot ,checking whether its connected to 5GHZ\n",token);
                        if(strstr(cli_mac_5g,token))
                        {
                            IHC_PRINT(" %s POD %s is connected to 5G interface after reboot from 2G interface  \n",__FUNCTION__,token);
                            IHC_PRINT("\n IHC:WirelessPOD_Radio5G_POD:%s \n",token);
                            report_t2("IHC:WirelessPOD_Radio5G_POD",'s',token);
                            str_fnd=1;
                        }
                    }
                    if(str_fnd == 0)      // the pod is newly connected to the 2g interface
                    {
                        IHC_PRINT(" POD is disconnected from the 2G interface = %s  \n",token);
                    }
                    token = strtok(NULL, " ");
                }
            }
            //checking any new devices connected to the interface
            token = strtok(cli_mac_2g, " ");
            while(token != NULL)
            {
                if( !strstr(cli_mac_2g_old,token) && !strstr(cli_mac_5g_old,token))
                {
                   IHC_PRINT(" %s is newly connected to the device's 2.4G interface\n",token);
                   IHC_PRINT("\n IHC:WirelessPOD_Radio2.4G_POD:%s \n",token);
                   report_t2("IHC:WirelessPOD_Radio2.4G_POD",'s',token);
                }
                token = strtok(NULL, " ");
            }
        }
        else
        {
           IHC_PRINT(" %s Currently no PODs connected to 2G interface and before reboot connected clients are %s\n",__FUNCTION__,cli_mac_2g_old);
        }
        //5GHZ to check if pods connected to 2g before reboot is connected back to device after reboot or not
        memset(tele_buff,0,sizeof(tele_buff));
        memset(tmp_buf,0,sizeof(tmp_buf));
        if( cli_mac_5g[0] != '\0' )
        {
            if ( cli_mac_5g_old[0] != '\0' )
            {
                rc=strcpy_s(tmp_buf,200,cli_mac_5g_old);
                ERR_CHK(rc);
                token=strtok(tmp_buf," ");
                while(token != NULL)
                {
                    str_fnd=0;
                    if(strstr(cli_mac_5g,token))
                    {
                        IHC_PRINT(" %s POD %s is connected to 5G interface before and after reboot  \n",__FUNCTION__,token);
                        IHC_PRINT("\n IHC:WirelessPOD_Radio5G_POD:%s \n",token);
                        report_t2("IHC:WirelessPOD_Radio5G_POD",'s',token);
                        str_fnd=1;
                    }
                    if(str_fnd == 0)                 // Checking whether the client is connected to 5GHZ after reboot
                    {
                        IHC_PRINT("Client %s is not connected to 5G after reboot ,checking whether its connected to 5GHZ\n",token);
                        if(strstr(cli_mac_2g,token))
                        {
                            IHC_PRINT(" %s POD %s is connected to 2.4G interface after reboot from 5G interface  \n",__FUNCTION__,token);
                            IHC_PRINT("\n IHC:WirelessPOD_Radio2.4G_POD:%s \n",token);
                            report_t2("IHC:WirelessPOD_Radio2.4G_POD",'s',token);
                            str_fnd=1;
                        }
                    }
                    if(str_fnd == 0)      // the pod is newly connected to the 2g interface
                    {
                        IHC_PRINT(" POD is disconnected from the 5G interface = %s  \n",token);
                    }
                    token=strtok(NULL," ");
                }
            }
            //checking any new devices connected to the interface
            token=strtok(cli_mac_5g," ");
            while(token != NULL)
            {
                if( !strstr(cli_mac_2g_old,token) && !strstr(cli_mac_5g_old,token))
                {
                   IHC_PRINT(" New Device connected to the 5G interface=%s  \n",token);
                   IHC_PRINT("\n IHC:WirelessPOD_Radio5G_POD:%s \n",token);
                   report_t2("IHC:WirelessPOD_Radio5G_POD",'s',token);
                }
                token=strtok(NULL," ");
            }
        }
        else
        {
           IHC_PRINT(" %s Currently no PODs connected to 5G interface and before reboot connected clients are %s\n",__FUNCTION__,cli_mac_5g_old);
        }
        //ETHERNET
        memset(tele_buff,0,sizeof(tele_buff));
        memset(tmp_buf,0,sizeof(tmp_buf));
        if(syscfg_get( NULL, "IHC_ETH_MAC_POD" , cli_mac_eth_old, sizeof(cli_mac_eth_old))!=0)
        {
           IHC_PRINT("%s syscfg get failed,Unable to get ETH POD details \n",__FUNCTION__);
        }
        if( cli_mac_eth[0] != '\0' )
        {
            if ( cli_mac_eth_old[0] != '\0' )
            {
                rc=strcpy_s(tmp_buf,200,cli_mac_eth_old);
                ERR_CHK(rc);
                token=strtok(tmp_buf," ");
                while(token != NULL)
                {
                    str_fnd=0;
                    if(strstr(cli_mac_eth,token))
                    {
                        IHC_PRINT(" %s POD %s is connected to ETH interface before and after reboot  \n",__FUNCTION__,token);
                        IHC_PRINT("\n IHC:EthernetPOD_Radio:%s \n",token);
                        report_t2("IHC:EthernetPOD_Radio",'s',token);
                        str_fnd=1;
                    }
                    if(str_fnd == 0)
                    {
                        IHC_PRINT(" POD is disconnected from the ETH interface = %s  \n",token);
                    }
                    token=strtok(NULL," ");
                }
            }
            memset(tele_buff,0,sizeof(tele_buff));
            //checking any new devices connected to the interface
            token=strtok(cli_mac_eth," ");
            while(token != NULL)
            {
                if( !strstr(cli_mac_eth_old,token) )
                {
                   IHC_PRINT(" %s is newly connected to the device's ETH interface  \n",token);
                   IHC_PRINT("\n IHC:EthernetPOD_Radio:%s \n",token);
                   report_t2("IHC:EthernetPOD_Radio",'s',token);
                }
                token=strtok(NULL," ");
            }
        }
        else
        {
           IHC_PRINT(" %s Currently no PODs connected to ETH interface and before reboot connected clients are %s\n",__FUNCTION__,cli_mac_eth_old);
        }
    }
}
int main(int argc,char* argv[])
{
    errno_t rc = -1;
    int ind    = -1;
    int Store_health=0;
    int Bootup_check=0;
    setenv("LOG4C_RCPATH","/rdklogger",1);
    rdk_logger_init(DEBUG_INI_NAME);
    if ( argc != 2 )
    {
        IHC_PRINT("Invalid number of arguments for ImagehealthChecker \n");
        exit(0);
    }
    //the runtime arugment should be either store-health or bootup-check.
    if ( ((rc = strcmp_s(STR_HLTH, strlen(STR_HLTH), argv[1] , &ind) == EOK) && !ind ) )
    {
        IHC_PRINT("ImagehealthChecker Execution begins .... with argument=%s \n",argv[1]);
        Store_health=1;
    }
    else if (((rc = strcmp_s(BT_CHCK, strlen(BT_CHCK), argv[1] , &ind) == EOK) && !ind ))
    {
        IHC_PRINT("ImagehealthChecker Execution begins .... with argument=%s \n",argv[1]);
        Bootup_check=1;
    }
    else
    {
        IHC_PRINT("Invalid argument ... Please Enter the proper argument name..... \n");
        exit(0);
    }

    t2_init("TandD");
    ccsp_hdl_ret = ccsp_handler_init();
    if ( 0 != ccsp_hdl_ret )
    {
        IHC_PRINT("%s ccsp bus handler init failed \n",__FUNCTION__);
        return -1;
    }
/* MESH POD MAC identification is not properly implemented , Will execute the code once the propery way implemented
       Check_PODs_Conn(STR_HLTH);
       Check_PODs_Conn(BT_CHCK);
*/
    if(Store_health == 1)
    {
        Check_ConnCli_Count(STR_HLTH);
        Check_Pwd_Change(STR_HLTH);
        Check_SSID_Change(STR_HLTH);
    }
    else if (Bootup_check == 1)
    {
        Check_ConnCli_Count(BT_CHCK);
        Check_Pwd_Change(BT_CHCK);
        Check_SSID_Change(BT_CHCK);
    }
/*  rc = strcmp_s("backup_cli_cnt", strlen("backup_cli_cnt"), argv[1] , &ind);
    ERR_CHK(rc);
    if((ind == 0) && (rc == EOK))
    {
        get_Clients_Count(STR_HLTH,NULL,0);
    } */
    ccsp_handler_exit();
    // INdicating IHC completed to backuplogs.sh file
    v_secure_system("touch /tmp/IHC_completed");
    IHC_PRINT("ImagehealthChecker Completed.... \n");
    return 0;
}
