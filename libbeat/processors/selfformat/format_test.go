package selfformat

import (
	"fmt"
	"testing"
)

func TestFormatAPINormalLog(t *testing.T) {
	var s = `[2020-07-07 16:38:07.111][INFO ][doAround com.enbrands.common.api.sdk.log2es.aspect.MethodLogAspect:136] response_out||trace_id=173286cd20525421c23b37bcec80800||interface_encoding=208_M_1001||host=172.16.0.102||client_ip=172.16.0.102||upper_client_ip=null||status_code=200||responseParam={"data":{"mixMobile":"152e45a23bbc61fea6d7fa5a6876f298","postalCode":0,"channel":0,"source":3,"createdAt":"2020-07-07 16:38:01","expiringPoint":0,"password":"","province":"","id":2063425,"updatedAt":"2020-07-07 16:38:01","qq":"","outMemberId":"2003617117","marriaged":0,"active":1,"phone":"","activitySource":"enbrands","msgSendStatus":0,"district":"","pointAdd":0,"usernameNum":0,"status":1,"flag":1,"city":"","bloodType":0,"point":100,"extInfo":"{\"source\":\"enbrands\"}","email":"","address":"","milkName":"","motherStatus":0,"sex":0,"birthType":0,"realName":"","babySex":0,"babyName":"","sourceMerchantNum":1000033,"memberIdentity":0,"username":""},"retCode":0,"retMsg":"查询成功"}||real_time=2020-07-07T16:38:07.110||timestamp=1594111087110||timeUsed=1`
	ts, n := FormatAPINormalLog(s)
	fmt.Printf("%+v  %+v\n", ts, n)
}
