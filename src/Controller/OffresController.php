<?php

// Définition du namespace du contrôleur
namespace App\Controller;

// Import des classes utilisées dans ce fichier
use App\Entity\Offres;
use App\Entity\User;
use App\Service\OffresService;
use OpenApi\Attributes as OA; // Pour la documentation Swagger / OpenAPI
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;
use Symfony\Bundle\SecurityBundle\Security;

// Toutes les routes de ce contrôleur commencent par /api/v1/offres
#[Route('/api/v1/offres', name: 'app_offres_')]
// Tag utilisé pour regrouper les endpoints dans la doc OpenAPI
#[OA\Tag(name: 'Offres')]
// Le contrôleur est déclaré final car il n'est pas destiné à être étendu
final class OffresController extends AbstractController
{
    // Injection du service métier et du service security via le constructeur (PHP 8 property promotion)
    public function __construct(private OffresService $offresService, private Security $security)
    {
    }

    // Route GET /api/v1/offres/list : lister les offres avec filtres optionnels
    #[Route('/list', name: 'list', methods: ['GET'])]
    #[OA\Get(
        path: "/api/v1/offres/list",
        summary: "List offres",
        // Paramètres de requête optionnels pour filtrer par devise
        parameters: [
            new OA\Parameter(
                name: "deviseSource",
                in: "query",
                required: false,
                schema: new OA\Schema(type: "string"),
                description: "Devise source (ex: XAF)"
            ),
            new OA\Parameter(
                name: "deviseCible",
                in: "query",
                required: false,
                schema: new OA\Schema(type: "string"),
                description: "Devise cible (ex: EUR)"
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
                            // Identifiant unique de l'offre
                            new OA\Property(property: "id", type: "integer"),
                            // Montant de l'offre
                            new OA\Property(property: "montant", type: "number", example: 1000),
                            // Statut de l'offre (ex: active)
                            new OA\Property(property: "statut", type: "string", example: "active"),
                            // Image associée, peut être nulle
                            new OA\Property(property: "image", type: "string", nullable: true),
                            // Devise source sous forme d'objet imbriqué
                            new OA\Property(
                                property: "deviseSource",
                                type: "object",
                                nullable: true,
                                properties: [
                                    new OA\Property(property: "id", type: "integer"),
                                    new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                    new OA\Property(property: "taux", type: "number", example: 650),
                                ]
                            ),
                            // Devise cible (code devise)
                            new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                            // Utilisateur sous forme d'objet imbriqué (nom, email et téléphone de celui qui a créé l'offre)
                            new OA\Property(
                                property: "user",
                                type: "object",
                                nullable: true,
                                properties: [
                                    new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                    new OA\Property(property: "email", type: "string", example: "jean@example.com"),
                                    new OA\Property(property: "phone", type: "string", example: "699000000"),
                                ]
                            ),
                            // Date et heure de création de l'offre
                            new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                        ]
                    )
                )
            ),
        ]
    )]
    public function list(Request $request): JsonResponse
    {
        try {
            // Récupérer les paramètres de requête optionnels
            $deviseSource = $request->query->get('deviseSource');
            $deviseCible = $request->query->get('deviseCible');

            // Choisir la méthode de filtrage selon les paramètres présents
            if ($deviseSource !== null && $deviseCible !== null) {
                $data = $this->offresService->getByBoth($deviseSource, $deviseCible);
            } elseif ($deviseSource !== null) {
                $data = $this->offresService->getByDeviseSource($deviseSource);
            } elseif ($deviseCible !== null) {
                $data = $this->offresService->getByDeviseCible($deviseCible);
            } else {
                $data = $this->offresService->getAll();
            }

            // Formater chaque offre pour respecter le format de réponse souhaité
            $data = array_map(fn(Offres $offre) => $this->format($offre), $data);

            // Retourner la liste dans une réponse JSON avec un statut 200 OK
            return $this->json([
                'status' => 'success',
                'data' => $data,
            ], Response::HTTP_OK);
        } catch (\RuntimeException $e) {
            // En cas d'erreur métier (ex: aucune offre trouvée), retourner 404
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    // Route GET /api/v1/offres/{id} : afficher le détail d'une offre
    #[Route('/{id}', name: 'show', methods: ['GET'])]
    #[OA\Get(
        path: "/api/v1/offres/{id}",
        summary: "Show an offre",
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
                description: "Offre details",
                content: new OA\JsonContent(
                    properties: [
                        new OA\Property(property: "id", type: "integer"),
                        new OA\Property(property: "montant", type: "number", example: 1000),
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(
                            property: "user",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                new OA\Property(property: "email", type: "string", example: "jean@example.com"),
                                new OA\Property(property: "phone", type: "string", example: "699000000"),
                            ]
                        ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                    ]
                )
            ),
            new OA\Response(
                response: 404,
                description: "Offre not found"
            )
        ]
    )]
    public function show(int $id): JsonResponse
    {
        try {
            // Récupérer une seule offre par son id via le service
            $offre = $this->offresService->getOne($id);

            // Retourner l'offre formatée
            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            // Retourner une erreur 404 si l'offre n'existe pas
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    // Route POST /api/v1/offres : créer une nouvelle offre (réservée admin)
    #[Route('', name: 'create', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    #[OA\Post(
        path: "/api/v1/offres",
        summary: "Create an offre",
        requestBody: new OA\RequestBody(
            required: true,
            content: new OA\JsonContent(
                // Champs obligatoires attendus dans le corps de la requête
                required: ["montant", "deviseSourceID", "deviseCible", "statut"],
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    // Devise cible de l'offre
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    // Statut de l'offre
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    // Image optionnelle
                    new OA\Property(property: "image", type: "string", nullable: true),
                    // Identifiant du taux de change choisi par l'admin
                    new OA\Property(property: "deviseSourceID", type: "integer", example: 1),
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
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                            new OA\Property(
                                property: "user",
                                type: "object",
                                nullable: true,
                                properties: [
                                    new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                    new OA\Property(property: "email", type: "string", example: "jean@example.com"),
                                    new OA\Property(property: "phone", type: "string", example: "699000000"),
                                ]
                            ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
                    ]
                )
            ),
        ]
    )]
    public function create(Request $request): JsonResponse
    {
        try {
            // Récupérer l'utilisateur connecté et le passer au service pour lier l'offre à son créateur
            $currentUser = $this->security->getUser();
            $offre = $this->offresService->create($request, $currentUser instanceof User ? $currentUser : null);

            // Retourner l'offre créée au format désiré avec un statut 201 Created
            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_CREATED);
        } catch (\InvalidArgumentException $e) {
            // Erreur de validation des données (mauvais format JSON ou champs manquants)
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_BAD_REQUEST);
        } catch (\RuntimeException $e) {
            // Autre erreur applicative
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_CONFLICT);
        }
    }

    // Route PUT /api/v1/offres/{id} : modifier une offre (réservée admin)
    #[Route('/{id}', name: 'update', methods: ['PUT'])]
    #[IsGranted('ROLE_ADMIN')]
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
                // Tous les champs sont optionnels en modification
                properties: [
                    new OA\Property(property: "montant", type: "number", example: 1000),
                    new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                    new OA\Property(property: "statut", type: "string", example: "active"),
                    new OA\Property(property: "image", type: "string", nullable: true),
                    // Permet de changer la devise source en envoyant un nouvel identifiant
                    new OA\Property(property: "deviseSourceID", type: "integer", example: 1),
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
                        new OA\Property(property: "statut", type: "string", example: "active"),
                        new OA\Property(property: "image", type: "string", nullable: true),
                        new OA\Property(
                            property: "deviseSource",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "id", type: "integer"),
                                new OA\Property(property: "monnaie", type: "string", example: "EUR"),
                                new OA\Property(property: "taux", type: "number", example: 650),
                            ]
                        ),
                        new OA\Property(property: "deviseCible", type: "string", example: "EUR"),
                        new OA\Property(
                            property: "user",
                            type: "object",
                            nullable: true,
                            properties: [
                                new OA\Property(property: "name", type: "string", example: "Jean Dupont"),
                                new OA\Property(property: "email", type: "string", example: "jean@example.com"),
                                new OA\Property(property: "phone", type: "string", example: "699000000"),
                            ]
                        ),
                        new OA\Property(property: "createdAt", type: "string", format: "date-time"),
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
            // Récupérer l'utilisateur connecté et le passer au service
            $currentUser = $this->security->getUser();
            $offre = $this->offresService->update($id, $request, $currentUser instanceof User ? $currentUser : null);

            // Retourner l'offre mise à jour formatée
            return $this->json([
                'status' => 'success',
                'data' => $this->format($offre),
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            // Offre introuvable ou données invalides
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        } catch (\RuntimeException $e) {
            // Conflit métier
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_CONFLICT);
        }
    }

    // Route DELETE /api/v1/offres/{id} : supprimer une offre (réservée admin)
    #[Route('/{id}', name: 'delete', methods: ['DELETE'])]
    #[IsGranted('ROLE_ADMIN')]
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
            // Supprimer l'offre via le service métier
            $message = $this->offresService->delete($id);

            // Retourner un message de succès
            return $this->json([
                'status' => 'success',
                'message' => $message['message'],
            ], Response::HTTP_OK);
        } catch (\InvalidArgumentException $e) {
            // Offre introuvable
            return $this->json([
                'status' => 'error',
                'message' => $e->getMessage(),
            ], Response::HTTP_NOT_FOUND);
        }
    }

    // Méthode privée de formatage : construit le tableau JSON de réponse pour une offre
    private function format(Offres $offre): array
    {
        // Récupérer l'utilisateur propriétaire de l'offre (peut être null)
        $user = $offre->getUser();
        // Récupérer le taux de change lié à l'offre (peut être null)
        $tauxChange = $offre->getTauxChange();

        // Construire le tableau de réponse exactement comme attendu par le frontend
        return [
            'id' => $offre->getId(),
            'montant' => $offre->getMontant(),
            'statut' => $offre->getStatut(),
            'image' => $offre->getImage(),
            // Objet imbriqué pour la devise source (avec id, monnaie et taux)
            'deviseSource' => $tauxChange ? [
                'id' => $tauxChange->getId(),
                'monnaie' => $tauxChange->getMonnaie(),
                'taux' => $tauxChange->getTaux(),
            ] : null,
            'deviseCible' => $offre->getDeviseCible(),
            // Objet imbriqué pour l'utilisateur (nom, email et téléphone de celui qui a créé l'offre)
            'user' => $user ? [
                'name' => $user->getName(),
                'email' => $user->getEmail(),
                'phone' => $user->getPhone(),
            ] : null,
            // Date de création formatée en ISO 8601 avec millisecondes et fuseau UTC (ex: 2026-06-16T18:26:43.599Z)
            'createdAt' => $offre->getCreatedAt()?->format('Y-m-d\TH:i:s.v\Z'),
        ];
    }
}
