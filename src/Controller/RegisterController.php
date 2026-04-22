<?php

namespace App\Controller;

use App\Service\RegisterService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use OpenApi\Attributes as OA;
use Symfony\Component\Routing\Attribute\Route;


#[OA\Tag(name: 'Authentication')]
#[Route('api/v1')]
final class RegisterController extends AbstractController
{
    
    public function __construct(private  RegisterService $registerService){}

    #[Route('/user/register', name: 'app_register_create', methods: ['POST'])]
    #[OA\Post(
        path:'/api/v1/user/register',
        summary: "User registration",
        description: "Allows registering a new user with name, phone, city, color, email, and password.",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "name", type: "string", example: "Beutsing jeanne"),
                    new OA\Property(property: "phone", type: "string", example: "+237 682341110"),
                    new OA\Property(property: "city", type: "string", example: "New York"),
                    new OA\Property(property: "email", type: "string", example: "beutsing@gmail.com"),
                    new OA\Property(property: "password", type: "string", example: "bk123")
                ]
            )
        ),
        responses: [
            new OA\Response(response: 201, description: "User created successfully",
                content: new OA\JsonContent(
                    properties: [    
                        new OA\Property(property: "status", type: "string", example: "The user has been created successfully"),
                        new OA\Property(property:"name", type: "string", example: "Beutsing jeanne"),
                    new OA\Property(property: "phone", type: "string", example: "+237 682341110"),
                    new OA\Property(property: "city", type: "string", example: "New York"),
                    new OA\Property(property: "email", type: "string", example: "beutsing@gmail.com"),
                    new OA\Property(property: "password", type: "string", example: "bk123")
                    ]
                )
            ),
            new OA\Response(response: 400, description: "Bad request",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "error", type: "string", example: "Invalid input data")
                    ]
                )
            ),
             new OA\Response(response: 409, description: "this user already exists",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "error", type: "string", example: "this user already exists")
                    ]
                )
            )
        ]      
    )]
    
    public function register(Request $request): JsonResponse
    {
        try {

        $user = $this->registerService->register($request);

        return new JsonResponse([$user,
            'status' => 'User created successfully',
        ], Response::HTTP_CREATED);

    } catch (\InvalidArgumentException $e) {
        return new JsonResponse(
            ['error' => $e->getMessage()],
            Response::HTTP_BAD_REQUEST
        );

    } catch (\RuntimeException $e) {
        return new JsonResponse(
            ['error' => $e->getMessage()],
            Response::HTTP_CONFLICT
        );
    }
    }

    #[Route('/user/list', name:'app_list', methods: ['GET'])]
    #[OA\Get(
        path: '/api/v1/user/list',
        summary: "List all users",
        description: "Retrieves a list of all registered users with their details.",
        responses:[
            new OA\Response(
                response:200,
                description:" list of users",
                content: new  OA\JsonContent(
                    type: "array",
                    items: new OA\Items(
                        type: "object",
                        properties: [
                            new OA\Property(property: "id", type: "integer", example: 1),
                            new OA\Property(property: "name", type: "string", example: "Beutsing Jeanne"),
                            new OA\Property(property: "phone", type: "string", example: "+237 692170034"),
                            new OA\Property(property: "city", type: "string", example: "Los Angeles"),
                            new OA\Property(property: "email", type: "string", example: "jeanne@gmail.com"),
                            new OA\Property(property: "roles", type: "array",
                                items: new OA\Items(type: "string", example: "ROLE_USER")
                            )]
                    )
                )
            )
        ]
    )]
    public function list():JsonResponse{
        $data= $this->registerService->listUsers();

        return new JsonResponse($data,Response::HTTP_OK);
    }

    #[Route('/user/modify/{id}', name:'app_modify', methods: ['PUT'])]
   #[OA\Put(
        path: '/api/v1/user/modify',
        summary: "Update user information",
        description: "Allows updating user information such as name, phone, city, color, email, password, and roles.",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                     new OA\Property(property: "name", type: "string", example: "Beutsing Jeanne", nullable: true),
                    new OA\Property(property: "phone", type: "string", example: "+237 692170034", nullable: true),
                    new OA\Property(property: "city", type: "string", example: "Los Angeles", nullable: true),
                    new OA\Property(property: "email", type: "string", example: "jeanne.doe@example.com", nullable: true),
                    new OA\Property(property: "password", type: "string", example: "admin123", nullable: true),
                     new OA\Property(property: "role",
                        type: "array",
                        nullable: true,
                        items: new OA\Items(type: "string", example: "ROLE_USER"),
                        description: "Array of roles to assign to the user"
                    )
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: "User updated successfully",
                content: new OA\JsonContent(
                    properties: [new OA\Property(property: "status", type: "string", example: "User updated successfully")]
                )
            ),
            new OA\Response(
                response: 400,
                description: "Bad request - invalid data",
                content: new OA\JsonContent(
                    properties: [new OA\Property(property: "error", type: "string", example: "Invalid role: ROLE_INVALID. Allowed roles: ROLE_USER, ROLE_ADMIN")]
                )
            ),
            new OA\Response(
                response: 404,
                description: "User not found",
                content: new OA\JsonContent(
                    properties: [new OA\Property(property: "error", type: "string", example: "User not found")]
                )
            )
        ]
    )]

    public function updateregister(Request $request,int $id): JsonResponse{
        try {
            $data = $this->registerService->updateregister($request, $id);
        } catch (\InvalidArgumentException $e) {
            return new JsonResponse(
                ['error' => $e->getMessage()],
                Response::HTTP_BAD_REQUEST
            );
        } catch (\RuntimeException $e) {
            return new JsonResponse(
                ['error' => $e->getMessage()],
                Response::HTTP_NOT_FOUND
            );
        }
        $data = $this->registerService->updateregister($request, $id);
        return new JsonResponse(['status' => 'User updated successfully'], Response::HTTP_OK);

    }

     #[Route('/user/delete/{id}', name:'app_regiter_delete', methods: ['DELETE'])]
     #[OA\Delete(
        path:'/api/v1/user/delete/{id}',
        summary:'Delete user by ID',
        description:'Allows delete a user b ID',
        parameters:[
            new OA\Parameter(
                name: 'id',
                in:'path',
                required: true,
                description:'ID of user to delete',
                schema: new OA\Schema(type: 'integer')
            )
        ],
        responses:[
            new OA\Response(
                response: 204,
                description: 'User deleted successfully'
            ),
            new OA\Response(
                response: 404,
                description: 'User not found',
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: 'error', type: 'string', example: 'User not found')
                    ]
                )
            )
        ]
        
     )]
     public function deleteUser(int $id): JsonResponse{
       try{
            $data=$this->registerService->deleteusers($id);

                return new JsonResponse($data,
                    Response::HTTP_OK);
       }
       catch (\RuntimeException $e) {
        return new JsonResponse(
            ['error' => $e->getMessage()],
            Response::HTTP_NOT_FOUND
        );
    }
        
    }
         
}