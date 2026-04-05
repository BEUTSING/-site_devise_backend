<?php

namespace App\Controller\SecurityController;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Attribute\Route;
use OpenApi\Attributes as OA;

#[OA\Tag(name: 'Authentication')]
final class LoginController extends AbstractController
{
 
    #[Route('/user/login', name: 'app_login', methods: ['POST'])]
    #[OA\Post(
        path: "/api/v1/user/login",
        summary: "User login",
        description: "Allows a user to log in with a username and password",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                type: "object",
                properties: [
                    new OA\Property(property: "email", type: "string", example: "user@example.com"),
                    new OA\Property(property: "password", type: "string", example: "password123")
                ]
            )
        ),
        responses: [
            new OA\Response(response: 200, description: "Login successful",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "token", type: "string", example: "eyJhbGciOiJIUzI1NiI...")
                    ]
                )
            ),
            new OA\Response(response: 401, description: "Invalid credentials",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "error", type: "string", example: "Please check your email and password.")
                    ]
                )
            )
        ]
    )]
    public function login(Request $request,UserPasswordHasherInterface $passwordHarsher,EntityManagerInterface $entityManager,JWTTokenManagerInterface $JWTManager): 
    JsonResponse{
        $date=json_decode($request->getContent(),true);

        $email = $date['email'] ?? null;
        $password = $date['password'] ?? null;
         if (!$email || !$password) {
            return new JsonResponse(['error' => 'Email and password are required'], Response::HTTP_BAD_REQUEST);
         }
         $user= $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

         if(!$user || !$passwordHarsher->isPasswordValid($user, $password)){
            return new JsonResponse(['error' => 'Please check your email and password.'], Response::HTTP_UNAUTHORIZED);
         }
         $token= $JWTManager->create($user);
            return new JsonResponse(['token' => $token], Response::HTTP_OK);
    }


    #[Route('/user/logout', name: 'app_logout', methods: ['POST'])]
    #[OA\Post(
        path:"/api/v1/user/logout",
        summary:"User logout",
        description:"Allows a user to log out",
        responses: [
        new OA\Response(response:200, description:"Logout successful"),
        ]
    )]
    public function logout(): JsonResponse
    {
        return new JsonResponse(['message' => 'Logged out successfully'], Response::HTTP_OK);
    }

}
