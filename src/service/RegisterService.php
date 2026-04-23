<?php

namespace App\Service;

use App\Entity\User ;
use App\Enum\RoleUser;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class RegisterService
{
    private $em;
    private $passwordHasher;
    private $userrepo;
    public function __construct(EntityManagerInterface $em,
                                 UserPasswordHasherInterface $passwordHasher,UserRepository $userrepo)
    {
        $this->em=$em;
        $this->passwordHasher=$passwordHasher;
        $this->userrepo=$userrepo;
    }
    //
    public function register(Request $request): array
    {
        $data = json_decode($request->getContent(), true);
         $required =['name','phone','city','email'];
         foreach($required as $field){
            if(empty($data[$field])){
                throw new \InvalidArgumentException('The field '.$field.' is required');
            }
         }
            if(!filter_var($data['email'],FILTER_VALIDATE_EMAIL)){
                throw new \InvalidArgumentException('The email is not valid');
            }
            $userexists=$this->userrepo->findOneBy(['email'=>$data['email']]);
            if($userexists){
                throw new \RuntimeException('this user already exists');
            }

        $user=new User();
        $user->setName($data['name']);
        $user->setPhone($data['phone']);
        $user->setCity($data['city']);
        $user->setEmail($data['email']);
        $user->setPassword($this->passwordHasher->hashPassword($user, $data['password']));

       $this->em->persist($user);
        $this->em->flush();
        $info[]=[
            "id"=>$user->getId(),
            "name"=>$user->getName(),
            "phone"=>$user->getPhone(),
            "city"=>$user->getCity(),
            "email"=>$user->getEmail()
        ];
        return $info;
    }
    //list users
    public function listUsers():array{
        $users=$this->userrepo->findAll();
        $data=[];
        foreach($users as $user){
            $data[]=[
                "id"=>$user->getId(),
                "name"=>$user->getName(),
                "phone"=>$user->getPhone(),
                "city"=>$user->getCity(),
                "email"=>$user->getEmail(),
                "roles"=>$user->getRoles()
            ];
        }
        return $data;
    }
    //update user

    public function updateregister(Request $request,int $id): array{

        $user =$this->userrepo->find($id);
        if (!$user) {

            throw new \InvalidArgumentException('User not found');
        } 

        $data=json_decode($request->getContent(), true);

             if(!filter_var($data['email'],FILTER_VALIDATE_EMAIL)){
                throw new \InvalidArgumentException('The email is not valid');
            }
            $userexists=$this->userrepo->findOneBy(['email'=>$data['email']]);
            if($userexists){
                throw new \RuntimeException('this user already exists');
            }
            if (isset($data['name'])) {
        $user->setName($data['name']);
    }

    if (isset($data['phone'])) {
        $user->setPhone($data['phone']);
    }

    if (isset($data['city'])) {
        $user->setCity($data['city']);
    }

       if(isset($data["role"])){
             $allowedRoles = array_column(RoleUser::cases(), 'value');

            foreach ($data["role"] as $r) {
                if (!in_array($r, $allowedRoles)) {
                   throw new \InvalidArgumentException(
                        'Invalid role: ' . $r . '. Allowed roles: ' . implode(', ', $allowedRoles)
                    );
                }
            }
            

         $user->setRoles($data["role"]);
       }
       if(isset($data['password'])){
                   $user->setPassword($this->passwordHasher->hashPassword($user,$data['password'] )); 

       }
        $this->em->flush();
        return ['status'=>'User updated successfully'];

    }
    //delete user

     public function deleteUsers(int $id ){

        $user=$this->userrepo->find($id);
        if(!$user){
        
             throw new \RuntimeException (
           'User not found'
        );
    }
         $this->em->remove($user);
        $this->em->flush();
        // log the delete of user

        return [
        'message' => 'User deleted successfully'
            ];     }
}