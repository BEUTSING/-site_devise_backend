<?php

namespace App\Controller;

use App\Service\OffresService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use OpenApi\Attributes as OA;

#[Route('/api/v1/offres',name:'app_offres_')]
#[OA\Tag(name: 'Offres')] 
final class OffresController extends AbstractController
{
    private OffresService $offresService;

    public function __construct(OffresService $offresService)
    {
        $this->offresService = $offresService;
    }

    #[Route('/list', name: 'list', methods: ['GET'])]
    #[IsGranted('ROLE_USER')]
    #[OA\Get(
        path: "/api/v1/offres/list",
        summary: "List offres",
        parameters: [
            new OA\Parameter(
                name: "deviseSource",
                in: "query",
                required: false,
                schema: new OA\Schema(type: "string"),
                description: "Devise source (ex: XAF)"
            ),
            new OA\Parameter(
                name:"deviseCible",
                in:"query",
                required:false,
                schema: new OA\Schema(type:"string"),
                description:"Devise cible (ex: EUR)"
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: "List of offres",
                content: new OA\JsonContent(
                    type: "array",
                    items: new OA\Items(
                        properties: [
                            new OA\Property(property: "id", type: "integer"),
                            new OA\Property(property: "montant", type: "number", example: 1000),
                            new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                            new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                            new OA\Property(property: "taux", type: "number", example: 650),
                            new OA\Property(property: "statut", type: "string", example: "active"),
                            new OA\Property(property: "image", type: "string", nullable: true),
                        ]
                    )
                )
            ),
             
        ]
    )]
    public function list(Request $request): JsonResponse
    {
        try {
            $deviseSource = $request->query->get('deviseSource');
            $deviseCible = $request->query->get('deviseCible');
            if ($deviseSource && $deviseCible) {
        $data = $this->offresService->getByBoth($deviseSource, $deviseCible);
        } elseif
             ($deviseSource !==null) {
                $data = $this->offresService->getByDeviseSource($deviseSource);
            } elseif ($deviseCible !== null) {
                $data = $this->offresService->getByDeviseCible($deviseCible);
            } else {
                            $data = $this->offresService->getAll();
            }

            return $this->json($data, Response::HTTP_OK);
        } catch (\RuntimeException $e) {
            return $this->json(['error' => $e->getMessage()], Response::HTTP_NOT_FOUND);
        }
    }


    /**
     *create an offre
     */
    #[Route(' ', name: 'create', methods: ['POST'])]
    #[OA\Post(
        path: "/api/v1/offres/create",
        summary: "Create an offre",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    new OA\Property(property: "taux", type: "number", example: 650),
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    new OA\Property(property: "image", type: "string", nullable: true)
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 201,
                description: "Offre created successfully",
                content: new OA\JsonContent( 
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(property: "taux", type: "number", example: 650),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        new OA\Property(property: "updatedAt", type: "string", format: "date-time")
                    ]
                )
            ),
           
        ]
    )]
    public function create(Request $request): JsonResponse
    {
        try {
            $data = $this->offresService->create($request);
            return $this->json($data, Response::HTTP_CREATED);
        } catch (\InvalidArgumentException $e) {
            return $this->json(['error' => $e->getMessage()], Response::HTTP_BAD_REQUEST);
        }
    }

    #[Route('/{id}', name: 'update', methods: ['PUT'])]
    #[OA\Put(
        path: "/api/v1/offres/{id}",
        summary: "Update an offre",
        parameters: [
            new OA\Parameter(
                name: "id",
                in: "path",
                required: true,
                schema: new OA\Schema(type: "integer")
            )
        ],
        requestBody: new OA\RequestBody(
            content: new OA\JsonContent(
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    new OA\Property(property: "taux", type: "number", example: 650),
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    new OA\Property(property: "image", type: "string", nullable: true)
                ]
            )
        ),
        responses: [
            new OA\Response(
                response: 200,
                description: "Offre updated successfully",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "deviseSource", type: "string", example: "XAF"),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(property: "taux", type: "number", example: 650),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        new OA\Property(property: "updatedAt", type: "string", format: "date-time")
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function update(int $id, Request $request): JsonResponse
    {
        try {
            $data = $this->offresService->update($id, $request);
            return $this->json($data, Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json(['error' => $e->getMessage()], Response::HTTP_NOT_FOUND);
        }
    }

    #[Route('/{id}', name: 'delete', methods: ['DELETE'])]
    #[OA\Delete(
        path: "/api/v1/offres/{id}",
        summary: "Delete an offre",
        parameters: [
            new OA\Parameter(
                name: "id",
                in: "path",
                required: true,
                schema: new OA\Schema(type: "integer")
            )
        ],
        responses: [
            new OA\Response(
                response: 200,
                description: "Deleted",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "message", type: "string", example: "Offre deleted successfully")
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function delete(int $id): JsonResponse
    {
        try {
            $message = $this->offresService->delete($id);
            return $this->json(['message' => $message], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            return $this->json(['error' => $e->getMessage()], Response::HTTP_NOT_FOUND);
        }
    }
}