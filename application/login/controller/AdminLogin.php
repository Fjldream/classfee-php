<?php

namespace app\login\controller;

use think\Controller;
use think\Db;
use think\JWT;
use think\Request;

class AdminLogin extends Controller
{
    public $code;
    private $jwtkey;
    private $pwdkey;
    public function __construct(Request $request = null)
    {
        parent::__construct($request);
        $this->code = config('code');
        $this->jwtkey = config('jwtkey');
        $this->pwdkey = config('salt');
    }

    /**
     * 显示资源列表
     *
     * @return \think\Response
     */
    public function index()
    {
        //

    }

    /**
     * 显示创建资源表单页.
     *
     * @return \think\Response
     */
    public function create()
    {
        //
        var_dump(crypt(md5(md5('12367s')),'fjldrea'));
    }

    /**
     * 保存新建的资源
     *
     * @param  \think\Request  $request
     * @return \think\Response
     */
    public function save(Request $request)
    {
        //注册方法
        $data = $_POST;
        $auname = $_POST['auname'];
        $name = Db::table('admintable')->where('auname','=',$auname)->find();
        if($name){
            return json([
                'code'=>$this->code['fail'],
                'msg'=>'账号已经存在！'
            ]);
        }else{
            //验证器
        $validate =validate('AdminLogin');
        $flag =$validate->scene('adminLogin')->check($data);
        if($flag){
            //如果验证通过
            $data['aupwd'] = crypt(md5(md5($data['aupwd'])),$this->pwdkey);
            $result = Db::table('admintable')->insert($data);
            if($result){
                return json([
                    'code'=>$this->code['success'],
                    'msg'=>'管理员账号注册成功!'
                ]);
            }
        }else{
            return json([
                'code'=>$this->code['fail'],
                'msg'=>$validate->getError()
            ]);
        }

        }
    }

    /**
     * 显示指定的资源
     *
     * @param  int  $id
     * @return \think\Response
     */
    public function read($id)
    {
        //登录方法
        $data = $this->request->get();
        //先验证账号是否存在
        $auname = $data['auname'];
        $flag = Db::table('admintable')->where('auname','=',$auname)->find();
        if($flag){
            $result = Db::table('admintable')->where('auname','=',$auname)->select();
            if(strcmp(crypt(md5(md5($data['aupwd'])),$this->pwdkey),$result[0]['aupwd'])==0){
                $payload =[
                    'auid'=>$result[0]['auid'],
                  'auname'=>$result[0]['auname'],
                  'avator'=>$result[0]['avator'],
                  'autname'=>$result[0]['autname']
                ];
                //登陆成功 签发token
               $token = JWT::getToken($payload,$this->jwtkey);
                return json([
                    'code'=>$this->code['success'],
                    'token'=>$token,
                    'msg'=>'登陆成功!'
                ]);
            }else{
                return json([
                    'code'=>$this->code['fail'],
                    'msg'=>'密码错误,请重新输入!'
                ]);
            }
        }else{
            return json([
                'code'=>$this->code['fail'],
                'msg'=>'账号不存在!'
            ]);
        }
    }

    /**
     * 显示编辑资源表单页.
     *
     * @param  int  $id
     * @return \think\Response
     */
    public function edit($id)
    {
        //
        $data = $this->request->get();
        $auid = $data['auid'];
        $flag = Db::table('admintable')->where('auid','=',$auid)->find();
        if($flag){
            // 该id存在
            $result = Db::table('admintable')->where('auid','=',$auid)->field('aupwd')->find();
            if(strcmp($result['aupwd'],crypt(md5(md5($data['oldaupwd'])),$this->pwdkey))==0){
                //旧密码是否输入正确
                $validate =validate('AdminLogin');
                $flag =$validate->scene('adminLoginRePwd')->check($data);
                if ($flag){
                    //修改数据库
                    $aupwd = ['aupwd'=>crypt(md5(md5($data['aupwd'])),$this->pwdkey)];
                   $result = Db::table('admintable')->where('auid','=',$data['auid'])->update($aupwd);
                    if($result){
                        return json([
                            'code'=>$this->code['success'],
                            'msg'=>'密码修改成功!'
                        ]);
                    }else{
                        return json([
                            'code'=>$this->code['fail'],
                            'msg'=>'密码修改失败!'
                        ]);
                    }
                }else{
                    return json([
                        'code'=>$this->code['fail'],
                        'msg'=>$validate->getError()
                    ]);
                }
            }else{
                return json([
                    'code'=>$this->code['fail'],
                    'msg'=>'旧密码输入错误!'
                ]);
            }
        }else{
            return json([
               'code'=>$this->code['fail'],
                'msg'=>'传入的id值不正确'
            ]);
        }

    }

    /**
     * 保存更新的资源
     *
     * @param  \think\Request  $request
     * @param  int  $id
     * @return \think\Response
     */
    public function update(Request $request, $id)
    {
        //
    }

    /**
     * 删除指定资源
     *
     * @param  int  $id
     * @return \think\Response
     */
    public function delete($id)
    {
        //
    }
}
